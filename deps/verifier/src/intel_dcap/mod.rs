use crate::intel_dcap::claims::prepare_custom_claims_map;
use crate::intel_dcap::collateral_service::PlatformCollaterals;
use crate::intel_dcap::error::describe_error;
use crate::TeeEvidenceParsedClaim;
use anyhow::{anyhow, bail};
use intel_tee_quote_verification_rs::{
    quote3_error_t, sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, sgx_ql_request_policy_t,
    sgx_qv_set_enclave_load_policy, tee_get_supplemental_data_version_and_size,
    tee_qv_get_collateral, tee_supp_data_descriptor_t, tee_verify_quote, QuoteCollateral,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::env;
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::mem;
use std::os::raw::c_char;
use std::time::{Duration, SystemTime};
use tracing::{debug, warn};
use urlencoding;

mod claims;
pub(crate) mod collateral_service;
pub(crate) mod pcs;
mod error;
#[cfg(any(feature = "tdx-verifier", feature = "sgx-verifier"))]
pub(crate) mod pck;

const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/";

#[derive(Debug, Default, Deserialize, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TcbUpdateType {
    #[default]
    Early,
    Standard,
}

#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
pub struct QcnlConfig {
    collateral_service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    use_secure_cert: Option<bool>,
    #[serde(default)]
    tcb_update_type: TcbUpdateType,
}

impl Default for QcnlConfig {
    fn default() -> Self {
        Self {
            collateral_service: INTEL_PCS_URL.to_string(),
            use_secure_cert: None,
            tcb_update_type: TcbUpdateType::Early,
        }
    }
}

pub fn set_qcnl_config(c: Option<QcnlConfig>) -> Result<(), std::io::Error> {
    env::var("QCNL_CONF_PATH")
        .map_err(std::io::Error::other)
        .and_then(File::create_new)
        .and_then(|mut f| {
            f.write_all(
                serde_json::to_string(&c.unwrap_or_default())
                    .map_err(|_| std::io::Error::from(ErrorKind::InvalidInput))?
                    .as_bytes(),
            )
        })
        .inspect_err(|e| match e.kind() {
            ErrorKind::Other => debug!(
                "QCNL_CONF_PATH environment variable is not set so configuration was skipped."
            ),
            ErrorKind::AlreadyExists => debug!("DCAP QCNL is already configured."),
            ErrorKind::PermissionDenied => {
                warn!("DCAP QCNL configuration failed due to permission error.")
            }
            ErrorKind::InvalidInput => {
                warn!("DCAP QCNL configuration failed due to invalid JSON.")
            }
            _ => warn!("DCAP QCNL configuration failed due to an unknown error."),
        })
        .inspect(|_| debug!("DCAP QCNL configuration was written to $QCNL_CONF_PATH."))
}

/// Proof-of-concept: build a [`QuoteCollateral`] from a pre-fetched
/// `platform_collaterals.json` file for a hardcoded TDX FMSPC.
///
/// This replaces `tee_qv_get_collateral()` for offline/cached use cases.
///
/// Uses version 3.1 collateral format: CRLs are raw binary DER (with null terminator).
/// All size fields in sgx_ql_qve_collateral_t include the terminating null byte.
fn collateral_from_platform_collaterals() -> anyhow::Result<QuoteCollateral> {
    const FMSPC: [u8; 6] = [0x50, 0x80, 0x6f, 0x00, 0x00, 0x00];
    const TDX_TEE_TYPE: u32 = 0x0000_0081;

    let data = std::fs::read_to_string("test_data/platform_collaterals.json")
        .map_err(|e| anyhow!("Failed to read platform_collaterals.json: {e}"))?;
    let pc = PlatformCollaterals::from_json_str(&data)
        .map_err(|e| anyhow!("Failed to parse platform_collaterals.json: {e}"))?;
    let col = pc.collaterals;

    let entry = col
        .tcbinfos
        .iter()
        .find(|e| e.fmspc == FMSPC)
        .ok_or_else(|| anyhow!("fmspc {:02x?} not found in platform_collaterals.json", FMSPC))?;

    let tdx_tcbinfo = entry
        .tdx_tcbinfo
        .as_ref()
        .ok_or_else(|| anyhow!("no tdx_tcbinfo for fmspc {:02x?}", FMSPC))?;

    // All fields in sgx_ql_qve_collateral_t include a null terminator in the size.
    fn to_cvec_null(mut bytes: Vec<u8>) -> Vec<c_char> {
        bytes.push(0);
        bytes.into_iter().map(|b| b as c_char).collect()
    }

    fn url_decode_null(s: &str) -> anyhow::Result<Vec<c_char>> {
        let bytes = urlencoding::decode(s)
            .map(|s| s.into_owned().into_bytes())
            .map_err(|e| anyhow!("URL decode failed: {e}"))?;
        Ok(to_cvec_null(bytes))
    }

    // Version 3.1: CRLs are raw binary DER with null terminator.
    fn der_hex_to_raw_null(hex_str: &str) -> anyhow::Result<Vec<c_char>> {
        let der = hex::decode(hex_str).map_err(|e| anyhow!("hex decode failed: {e}"))?;
        Ok(to_cvec_null(der))
    }

    // The PCK CRL issuer chain is keyed by CA type; prefer PLATFORM, fall back to PROCESSOR.
    let pck_chain_raw = col
        .certificates
        .pck_crl_issuer_chain
        .get("PLATFORM")
        .or_else(|| col.certificates.pck_crl_issuer_chain.get("PROCESSOR"))
        .ok_or_else(|| anyhow!("no PCK CRL issuer chain in certificates"))?;

    // For TDX with PLATFORM CA type, use platformCrl; fall back to processorCrl.
    let pck_crl_hex = col
        .pckcacrl
        .platform_crl
        .as_deref()
        .unwrap_or(&col.pckcacrl.processor_crl);

    Ok(QuoteCollateral {
        major_version: 3,
        minor_version: 1,
        tee_type: TDX_TEE_TYPE,
        tcb_info: to_cvec_null(
            serde_json::to_vec(tdx_tcbinfo)
                .map_err(|e| anyhow!("Failed to serialize tdx_tcbinfo: {e}"))?,
        ),
        tcb_info_issuer_chain: url_decode_null(&col.certificates.tcb_info_issuer_chain)?,
        qe_identity: to_cvec_null(col.tdqeidentity.into_bytes()),
        qe_identity_issuer_chain: url_decode_null(
            &col.certificates.enclave_identity_issuer_chain,
        )?,
        pck_crl: der_hex_to_raw_null(pck_crl_hex)?,
        pck_crl_issuer_chain: url_decode_null(pck_chain_raw)?,
        root_ca_crl: der_hex_to_raw_null(&col.rootcacrl)?,
    })
}

pub async fn ecdsa_quote_verification(quote: &[u8]) -> anyhow::Result<Map<String, Value>> {
    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
    };

    // Call DCAP quote verify library to set QvE loading policy to multi-thread
    // We only need to set the policy once; otherwise, it will return the error code 0xe00c (SGX_QL_UNSUPPORTED_LOADING_POLICY)
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        match sgx_qv_set_enclave_load_policy(
            sgx_ql_request_policy_t::SGX_QL_PERSISTENT_QVE_MULTI_THREAD,
        ) {
            quote3_error_t::SGX_QL_SUCCESS => {
                debug!("Info: sgx_qv_set_enclave_load_policy successfully returned.")
            }
            err => warn!(
                "Error: sgx_qv_set_enclave_load_policy failed: {}",
                describe_error(err)
            ),
        }
    });

    match tee_get_supplemental_data_version_and_size(quote) {
        Ok((supp_ver, supp_size)) => {
            if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
                debug!("tee_get_quote_supplemental_data_version_and_size successfully returned.");
                debug!(
                    "Info: latest supplemental data major version: {}, minor version: {}, size: {}",
                    u16::from_be_bytes(supp_ver.to_be_bytes()[..2].try_into()?),
                    u16::from_be_bytes(supp_ver.to_be_bytes()[2..].try_into()?),
                    supp_size,
                );
                supp_data_desc.data_size = supp_size;
            } else {
                warn!("Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.")
            }
        }
        Err(e) => bail!(
            "tee_get_quote_supplemental_data_size failed: {}",
            describe_error(e)
        ),
    }

    let collateral = match collateral_from_platform_collaterals() {
        Ok(c) => Some(c),
        Err(e) => {
            warn!("collateral_from_platform_collaterals failed: {e}, falling back to tee_qv_get_collateral");
            match tee_qv_get_collateral(quote) {
                Ok(c) => {
                    debug!("tee_qv_get_collateral successfully returned.");
                    Some(c)
                }
                Err(e) => {
                    warn!("tee_qv_get_collateral failed: {}", describe_error(e));
                    None
                }
            }
        }
    };

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    let p_supplemental_data = match supp_data_desc.data_size {
        0 => None,
        _ => Some(&mut supp_data_desc),
    };

    // call DCAP quote verify library for quote verification
    let (collateral_expiration_status, quote_verification_result) = tee_verify_quote(
        quote,
        collateral.as_ref(),
        current_time,
        None,
        p_supplemental_data,
    )
    .map_err(|e| anyhow!("tee_verify_quote failed: {}", describe_error(e)))?;

    debug!("tee_verify_quote successfully returned.");

    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED => {
            Ok(prepare_custom_claims_map(
                &mut supp_data,
                collateral_expiration_status,
                quote_verification_result,
            ))
        }
        terminal_result => {
            bail!(
                "Verification completed with Terminal result: {:?} ({:#04x})",
                terminal_result,
                terminal_result as u32
            );
        }
    }
}

pub fn extend_using_custom_claims(
    claim: &mut TeeEvidenceParsedClaim,
    custom: Map<String, Value>,
) -> anyhow::Result<()> {
    let Value::Object(ref mut map) = claim else {
        bail!("failed to extend the claim, not an object");
    };
    map.extend(custom);
    anyhow::Ok(())
}
