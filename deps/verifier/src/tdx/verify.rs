use super::quote::{cert_data_start, parse_certification_data_v4, parse_tdx_quote};
use crate::intel_dcap::collateral_service::*;
use crate::intel_dcap::pck;
use crate::sgx::types::*;
use anyhow::{anyhow, bail};
use chrono::{DateTime, Utc};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::Public;
use openssl::sha::{sha256, Sha256};
use openssl::stack::Stack;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{
    store::X509StoreBuilder, CrlStatus, X509Crl, X509StoreContext, X509VerifyResult, X509,
};
use openssl::{ec::EcGroup, ec::EcKey, ec::EcKeyRef, ecdsa::EcdsaSig};
use scroll::Pread;
use std::sync::LazyLock;
use x509_parser::prelude::{FromDer, X509Certificate};

static INTEL_PCS_ROOT_CA: LazyLock<X509> = LazyLock::new(|| {
    X509::from_pem(include_bytes!(
        "Intel_SGX_Provisioning_Certification_RootCA.pem"
    ))
    .expect("Load Intel SGX Provisioning Certification Root CA")
});

const SGX_PCK_PLATFORM_CA: &str = "Intel SGX PCK Platform CA";
const SGX_PCK_PROCESSOR_CA: &str = "Intel SGX PCK Processor CA";

// quote3_error_t::TEE_SUCCESS => "Success.",
// quote3_error_t::SGX_QL_ERROR_UNEXPECTED => "An unexpected internal error occurred.",
// quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER => "The platform quote provider library rejected the input.",
// quote3_error_t::SGX_QL_ERROR_OUT_OF_MEMORY => "Heap memory allocation error in library or enclave.",
// quote3_error_t::SGX_QL_ERROR_ECDSA_ID_MISMATCH => "Expected ECDSA_ID does not match the value stored in the ECDSA Blob.",
// quote3_error_t::SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR => "The ECDSA blob pathname is too large.",
// quote3_error_t::SGX_QL_FILE_ACCESS_ERROR => "Not able to find the ‘label’ or there was a problem writing or retrieving the data.",
// quote3_error_t::SGX_QL_ERROR_STORED_KEY => "Cached ECDSA key is invalid.",
// quote3_error_t::SGX_QL_ERROR_PUB_KEY_ID_MISMATCH => "Cached ECDSA key does not match requested key.",
// quote3_error_t::SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME => " PCE use the incorrect signature scheme.",
// quote3_error_t::SGX_QL_ATT_KEY_BLOB_ERROR => "There is a problem with the attestation key blob.",
// quote3_error_t::SGX_QL_UNSUPPORTED_ATT_KEY_ID => "Unsupported attestation key ID.",
// quote3_error_t::SGX_QL_UNSUPPORTED_LOADING_POLICY => "Selected policy is not supported by the quoting library.",
// quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE => "Unable to load the PCE enclave.",
// quote3_error_t::SGX_QL_PLATFORM_LIB_UNAVAILABLE => "The Quote Verification Library could not locate the provider library.",
// quote3_error_t::SGX_QL_ATT_KEY_NOT_INITIALIZED => "Platform quoting infrastructure does not have the attestation key available to generate quotes.",
// quote3_error_t::SGX_QL_ATT_KEY_CERT_DATA_INVALID => "Certification data retrieved from the platform quote provider library is invalid.",
// quote3_error_t::SGX_QL_NO_PLATFORM_CERT_DATA => "The platform quote provider library doesn't have the platform certification data for this platform.",
// quote3_error_t::SGX_QL_OUT_OF_EPC => "Not enough memory in the EPC to load the enclave.",
// quote3_error_t::SGX_QL_ERROR_REPORT => "The QvE report can NOT be verified.",
// quote3_error_t::SGX_QL_ENCLAVE_LOST => "Enclave was lost after power transition or used in a child process created by linux:fork().",
// quote3_error_t::SGX_QL_INVALID_REPORT => "Report MAC check failed on an application report.",
// quote3_error_t::SGX_QL_ENCLAVE_LOAD_ERROR => "Unable to load one of the quote library enclaves required to initialize the attestation key. Could be due to file I/O error or some other loading infrastructure errors.",
// quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_QE_REPORT => "The QE was unable to generate its own report targeting the application enclave either because the QE doesn't support this feature there is an enclave compatibility issue.",
// quote3_error_t::SGX_QL_KEY_CERTIFCATION_ERROR => "Caused when the provider library returns an invalid TCB (too high).",
// quote3_error_t::SGX_QL_NETWORK_ERROR => "If the platform quote provider library uses the network to retrieve the QVE Identity, this error will be returned when it encounters network connectivity problems. Could be due to sgx_default_qcnl.conf wrong configuration.",
// quote3_error_t::SGX_QL_MESSAGE_ERROR => "If the platform quote provider library uses message protocols to retrieve the QVE Identity collateral, this error will be returned when it encounters any protocol problems.",
// quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA => "The platform quote provider library does not have the quote verification collateral data available.",
// quote3_error_t::SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED => "The quote verifier doesn’t support the certification data in the Quote. Currently, the Intel QVE only supported CertType = 5.",
// quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED => "The inputted quote format is not supported. Either because the header information is not supported or the quote is malformed in some way.",
// quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT => "The QVE was unable to generate its own report targeting the application enclave because there is an enclave compatibility issue.",
// quote3_error_t::SGX_QL_QE_REPORT_INVALID_SIGNATURE => "The signature over the QE Report is invalid.",
// quote3_error_t::SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT => "The quote verifier doesn’t support the format of the application REPORT the Quote.",
// quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT => "The format of the PCK certificate is unsupported.",
// quote3_error_t::SGX_QL_PCK_CERT_CHAIN_ERROR => "There was an error verifying the PCK certificate signature chain including PCK certificate revocation.",
// quote3_error_t::SGX_QL_TCBINFO_UNSUPPORTED_FORMAT => "The format of the TCBInfo structure is unsupported.",
// quote3_error_t::SGX_QL_TCBINFO_MISMATCH => "PCK certificate FMSPc does not match the TCBInfo FMSPc.",
// quote3_error_t::SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT => "The format of the QEIdentity structure is unsupported.",
// quote3_error_t::SGX_QL_QEIDENTITY_MISMATCH => "The Quote’s QE doesn’t match the inputted expected QEIdentity.",
// quote3_error_t::SGX_QL_TCB_OUT_OF_DATE => "TCB out of date.",
// quote3_error_t::SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED => "TCB out of date and Configuration needed.",
// quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE => "SGX enclave identity out of date.",
// quote3_error_t::SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE => "SGX enclave report ISV SVN out of date.",
// quote3_error_t::SGX_QL_QE_IDENTITY_OUT_OF_DATE => "QE identity out of date.",
// quote3_error_t::SGX_QL_SGX_TCB_INFO_EXPIRED => "SGX TCB info expired.",
// quote3_error_t::SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED => "SGX PCK certificate chain expired.",
// quote3_error_t::SGX_QL_SGX_CRL_EXPIRED => "SGX CRL expired.",
// quote3_error_t::SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED => "SGX signing certificate chain expired.",
// quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED => "SGX enclave identity expired.",
// quote3_error_t::SGX_QL_PCK_REVOKED => "PCK is revoked.",
// quote3_error_t::SGX_QL_TCB_REVOKED => "TCB is revoked.",
// quote3_error_t::SGX_QL_TCB_CONFIGURATION_NEEDED => "TCB configuration needed.",
// quote3_error_t::SGX_QL_UNABLE_TO_GET_COLLATERAL => "Unable to get collateral.",
// quote3_error_t::SGX_QL_ERROR_INVALID_PRIVILEGE => "No enough privilege to perform the operation.",
// quote3_error_t::SGX_QL_NO_QVE_IDENTITY_DATA => "The platform quote provider library does not have the QVE identity data available.",
// quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT => "Unsupported CRL format.",
// quote3_error_t::SGX_QL_QEIDENTITY_CHAIN_ERROR => "There was an error verifying the QEIdentity signature chain including QEIdentity revocation.",
// quote3_error_t::SGX_QL_TCBINFO_CHAIN_ERROR => "There was an error verifying the TCBInfo signature chain including TCBInfo revocation.",
// quote3_error_t::SGX_QL_ERROR_QVL_QVE_MISMATCH => "Only returned when the quote verification library supports both the untrusted mode of verification and the QvE backed mode of verification. This error indicates that the 2 versions of the verification modes are different. Most caused by using a QvE that does not match the version of the DCAP installed.",
// quote3_error_t::SGX_QL_TCB_SW_HARDENING_NEEDED => "TCB up to date but SW Hardening needed.",
// quote3_error_t::SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED => "TCB up to date but Configuration and SW Hardening needed.",
// quote3_error_t::SGX_QL_UNSUPPORTED_MODE => "The platform has been configured to use the out-of-process implementation of quote generation.",
// quote3_error_t::SGX_QL_NO_DEVICE => "Can't open SGX device. This error happens only when running in out-of-process mode.",
// quote3_error_t::SGX_QL_SERVICE_UNAVAILABLE => "Indicates AESM didn't respond or the requested service is not supported. This error happens only when running in out-of-process mode.",
// quote3_error_t::SGX_QL_NETWORK_FAILURE => "Network connection or proxy setting issue is encountered. This error happens only when running in out-of-process mode.",
// quote3_error_t::SGX_QL_SERVICE_TIMEOUT => "The request to out-of-process service has timed out. This error happens only when running in out-of-process mode.",
// quote3_error_t::SGX_QL_ERROR_BUSY => "The requested service is temporarily not available. This error happens only when running in out-of-process mode.",
// quote3_error_t::SGX_QL_UNKNOWN_MESSAGE_RESPONSE => "Unexpected error from the cache service.",
// quote3_error_t::SGX_QL_PERSISTENT_STORAGE_ERROR => "Error storing the retrieved cached data in persistent memory.",
// quote3_error_t::SGX_QL_ERROR_MESSAGE_PARSING_ERROR => "Generic message parsing error from the attestation infrastructure while retrieving the platform data.",
// quote3_error_t::SGX_QL_PLATFORM_UNKNOWN => "This platform is an unrecognized SGX platform.",
// quote3_error_t::SGX_QL_QVEIDENTITY_MISMATCH => "The QvE identity info from report doesn’t match to value in sgx_dcap_tvl.",
// quote3_error_t::SGX_QL_QVE_OUT_OF_DATE => "The input QvE ISV SVN threshold is smaller than actual QvE ISV SVN.",
// quote3_error_t::SGX_QL_PSW_NOT_AVAILABLE => "SGX PSW library cannot be loaded, could be due to file I/O error.",
// From CertType=5 ("PCK Leaf Cert || Intermediate CA Cert || Root CA Cert") we get:
const PCK_LEAF: usize = 0;
const INTERMEDIATE_CA: usize = 1;
const ROOT_CA: usize = 2;

fn get_tcb_status(
    ref_tcb: &TcbLevel,
    pck_cpu_svns: &[u8],
    pck_cpu_pcesvn: u16,
    td_svns: Option<&[u8]>,
) -> bool {
    // Step 3.a: All SGX TCB Comp SVNs from the PCK certificate must be >= corresponding
    // values in sgxtcbcomponents of the TCB Level (element-wise, not lexicographic).
    let sgx_ok = ref_tcb.tcb.sgxtcbcomponents.as_ref().is_some_and(|r| {
        pck_cpu_svns.len() == r.0.len()
            && pck_cpu_svns
                .iter()
                .zip(r.0.iter())
                .all(|(cert, reference)| cert >= &reference.svn)
    });
    if !sgx_ok {
        return false;
    }

    // Step 3.b: PCESVN from PCK certificate must be >= the value in TCB Level.
    if pck_cpu_pcesvn < ref_tcb.tcb.pcesvn.unwrap_or(0) {
        return false;
    }

    // Step 3.c (TDX only): TEE TCB SVNs from the TD Report must be >= corresponding
    // values in tdxtcbcomponents of the TCB Level (element-wise).
    // Use indices 0..15 when TEE TCB SVN[1] == 0, or 2..15 otherwise.
    let Some(tds) = td_svns else {
        return true; // SGX: no TEE TCB SVN to check
    };

    ref_tcb.tcb.tdxtcbcomponents.as_ref().is_some_and(|r| {
        let idx = if tds[1] == 0 { 0 } else { 2 };
        tds[idx..]
            .iter()
            .zip(r.0[idx..].iter())
            .all(|(td, reference)| td >= &reference.svn)
    })
}

fn cert_has_common_name(cert: &X509, cn: &str) -> bool {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|cn| cn.data().as_utf8().ok())
        .is_some_and(|s| s.to_string() == cn)
}

fn ecdsa_signature_matches(
    data_hash: &[u8],
    r: &[u8],
    s: &[u8],
    pub_key: &EcKeyRef<Public>,
) -> Result<bool, ErrorStack> {
    let br = BigNum::from_slice(r)?;
    let bs = BigNum::from_slice(s)?;

    let ecdsa_sig = EcdsaSig::from_private_components(br, bs)?;

    ecdsa_sig.verify(data_hash, pub_key)
}

pub async fn dcap_verify(
    quote: &[u8],
    t: &DateTime<Utc>,
    collateral: &impl CollateralService,
) -> anyhow::Result<bool> {
    let qt = parse_tdx_quote(quote)?;

    // TODO: validate header: attestation key type, TEE type

    let start = cert_data_start(&qt);

    let cert_len: u32 = quote.pread::<u32>(start).expect("MUST succeed");

    let end = start + std::mem::size_of::<u32>() + cert_len as usize;
    if quote.len() < end {
        bail!("wrong quote size");
    }

    let qe = parse_certification_data_v4(&quote[start + std::mem::size_of::<u32>()..])?;

    let x = BigNum::from_slice(&qe.quote_signature.pkey_x_coord)?;
    let y = BigNum::from_slice(&qe.quote_signature.pkey_y_coord)?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let pub_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;

    ecdsa_signature_matches(
        &sha256(&quote[..start]),
        &qe.quote_signature.sig_r,
        &qe.quote_signature.sig_s,
        pub_key.as_ref(),
    )
    .map_err(|e| anyhow!("ECDSA signature error: {e}"))
    .and_then(|r| {
        if !r {
            Err(anyhow!("Quote ECDSA signature verification failed."))
        } else {
            println!("OK");
            Ok(())
        }
    })?;

    // = Start QE Identity Checks =
    //
    // Test that the AK pubkey and QE authentication data are bound to
    // Quoting Enclave's Report Data:
    // sha256(Attestation Key || QE Authentication Data) || 32-0x00’s
    let mut report_data = [0u8; 64];
    let mut hasher = Sha256::new();

    hasher.update(&qe.quote_signature.pkey_x_coord);
    hasher.update(&qe.quote_signature.pkey_y_coord);
    hasher.update(qe.qe_certification_data.qe_authentication.as_slice());
    let hash = hasher.finish();

    report_data[..32].copy_from_slice(&hash);

    let qer = (qe.qe_certification_data.qe_report.report)
        .pread::<sgx_report_body_t>(0)
        .map_err(|e| anyhow!("Foo {}", e))?;

    if report_data != qer.report_data {
        println!("QE Report ReportData mismatch!");
    }

    let pck_certificates = X509::stack_from_pem(&qe.qe_certification_data.certificates)?;
    let public_key = pck_certificates[PCK_LEAF].public_key()?;
    let ec_key = EcKey::try_from(public_key)?;

    ecdsa_signature_matches(
        &sha256(&qe.qe_certification_data.qe_report.report),
        &qe.qe_certification_data.qe_report.sig_r,
        &qe.qe_certification_data.qe_report.sig_s,
        ec_key.as_ref(),
    )
    .map_err(|e| anyhow!("ECDSA signature error: {e}"))
    .and_then(|r| {
        if !r {
            Err(anyhow!("Quote ECDSA signature verification failed."))
        } else {
            println!("OK");
            Ok(())
        }
    })?;

    if pck_certificates[ROOT_CA].issued(&pck_certificates[ROOT_CA]) != X509VerifyResult::OK {
        println!("{:?}", pck_certificates[ROOT_CA]);
    }

    if pck_certificates[ROOT_CA].issued(&pck_certificates[INTERMEDIATE_CA]) != X509VerifyResult::OK
    {
        println!("{:?}", pck_certificates[INTERMEDIATE_CA]);
    }

    if pck_certificates[INTERMEDIATE_CA].issued(&pck_certificates[PCK_LEAF]) != X509VerifyResult::OK
    {
        println!("{:?}", pck_certificates[PCK_LEAF]);
    }

    let mut param = X509VerifyParam::new()?;
    param.set_time(t.timestamp());
    // TODO: add X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL once add_crl() becomes available.
    param.set_flags(X509VerifyFlags::USE_CHECK_TIME)?;

    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(INTEL_PCS_ROOT_CA.clone()).unwrap();
    builder.set_param(param.as_ref())?;
    let trust_anchor = builder.build();

    let mut intermediate_certs = Stack::<X509>::new()?;
    intermediate_certs.push(pck_certificates[INTERMEDIATE_CA].clone())?;

    let mut context = X509StoreContext::new()?;
    let verified = context
        .init(
            &trust_anchor,
            &pck_certificates[PCK_LEAF],
            &intermediate_certs,
            |c| c.verify_cert(),
        )
        .map_err(|e| anyhow!(e.to_string()))?;

    if !verified {
        bail!("Report certificate chain failed to verify");
    }

    let CollateralData { body: raw_qe_identity, cert_chain: qe_identity_chain } = collateral
        .get(CollateralType::QeIdentity(&IntelTee::Tdx))
        .await
        .expect("Pull QE Identity");

    let qe_identity_cert_chain = X509::stack_from_pem(&qe_identity_chain.unwrap())?;

    let mut context = X509StoreContext::new()?;
    let verified = context
        .init(
            &trust_anchor,
            &qe_identity_cert_chain[0],
            &intermediate_certs,
            |c| c.verify_cert(),
        )
        .map_err(|e| anyhow!(e.to_string()))?;

    if !verified {
        bail!("QE identity certificate chain failed to verify");
    }
    let q: QeIdentity = serde_json::from_slice(raw_qe_identity.as_slice()).expect("Deserialize");

    let bytes = serde_json::to_vec(&q.enclave_identity).expect("Serialize to bytes");

    let pub_key = qe_identity_cert_chain[0]
        .public_key()
        .expect("Get public key from the signing certificate");

    let ec_key = EcKey::try_from(pub_key)?;
    ecdsa_signature_matches(
        &sha256(&bytes),
        &q.signature[..32],
        &q.signature[32..],
        ec_key.as_ref(),
    )
    .map_err(|e| anyhow!("ECDSA signature error: {e}"))
    .and_then(|r| {
        if !r {
            Err(anyhow!("Quote ECDSA signature verification failed."))
        } else {
            println!("Enclave Identity Signature OK");
            Ok(())
        }
    })?;

    if q.enclave_identity.id.as_str() == "TD_QE" {
        println!("QE ID OK!");
    }

    let flags_mask: [u8; 8] = q.enclave_identity.attributes_mask[..8].try_into()?;
    let flags: [u8; 8] = q.enclave_identity.attributes[..8].try_into()?;

    let xfrm_mask: [u8; 8] = q.enclave_identity.attributes_mask[8..].try_into()?;
    let xfrm: [u8; 8] = q.enclave_identity.attributes[8..].try_into()?;

    println!(
        "misc check: {}",
        (u32::from_le_bytes(qer.misc_select)
            & u32::from_le_bytes(q.enclave_identity.miscselect_mask))
            == u32::from_le_bytes(q.enclave_identity.miscselect)
    );
    println!(
        "attributes flags check: {}",
        (u64::from_le_bytes(qer.attributes.flags) & u64::from_le_bytes(flags_mask))
            == u64::from_le_bytes(flags)
    );
    println!(
        "attributes xfrm check: {}",
        (u64::from_le_bytes(qer.attributes.xfrm) & u64::from_le_bytes(xfrm_mask))
            == u64::from_le_bytes(xfrm)
    );
    println!(
        "mrsigner check: {}",
        q.enclave_identity.mrsigner == qer.mr_signer
    );
    println!(
        "isvprodid check: {}",
        q.enclave_identity.isvprodid == u16::from_le_bytes(qer.isv_prod_id)
    );

    let qe_tcb_level =
        q.enclave_identity.tcb_levels.iter().find(|lvl| {
            lvl.tcb.isvsvn.unwrap_or(u8::MAX) as u16 <= u16::from_le_bytes(qer.isv_svn)
        });

    // FAIL on None!
    println!("QE TCB LEVEL {:?}", qe_tcb_level.unwrap().tcb_status);

    // = End QE Identity Checks =

    let CollateralData { body: raw_rootca_crl, .. } = collateral
        .get(CollateralType::RootCaCrl(
            qe_identity_cert_chain[0]
                .crl_distribution_points()
                .as_ref()
                .and_then(|points| points.get(0))
                .and_then(|point| point.distpoint())
                .and_then(|distpoint| distpoint.fullname())
                .and_then(|fullname| fullname.get(0))
                .and_then(|name| name.uri()),
        ))
        .await
        .expect("Root CA CRL");

    let rootca_crl = X509Crl::from_der(&raw_rootca_crl)?;
    // TODO: check next_update() and verify()
    match rootca_crl.get_by_cert(&pck_certificates[INTERMEDIATE_CA]) {
        CrlStatus::NotRevoked => println!("Intermediate NotRevoked"),
        CrlStatus::Revoked(r) => println!("Revoked on {:?}", r.revocation_date().to_string()),
        CrlStatus::RemoveFromCrl(r) => {
            println!("Removed from Crl on {:?}", r.revocation_date().to_string())
        }
    }

    println!("Root CA CRL issuer {:?}", rootca_crl.issuer_name());
    let trusted_pub_key = pck_certificates[ROOT_CA].public_key()?;
    println!(
        "verify root ca crl {:?}",
        rootca_crl.verify(&trusted_pub_key).unwrap()
    );
    let ca = {
        if cert_has_common_name(&pck_certificates[INTERMEDIATE_CA], SGX_PCK_PLATFORM_CA) {
            Some("platform")
        } else if cert_has_common_name(&pck_certificates[INTERMEDIATE_CA], SGX_PCK_PROCESSOR_CA) {
            Some("processor")
        } else {
            None
        }
    };

    let CollateralData { body: pck_crl_der_bytes, cert_chain: raw_pck_crl_chain } = collateral
        .get(CollateralType::PckCrl(ca.unwrap(), "der"))
        .await
        .expect("pck crl");

    let pck_crl = X509Crl::from_der(&pck_crl_der_bytes)?;
    println!("PCK CRL issuer {:?}", pck_crl.issuer_name());

    let trusted_pub_key = pck_certificates[INTERMEDIATE_CA].public_key()?;

    println!(
        "verify pck crl {:?}",
        pck_crl.verify(&trusted_pub_key).unwrap()
    );

    let pck_crl_cert_chain = X509::stack_from_pem(&raw_pck_crl_chain.unwrap())?;

    let mut context = X509StoreContext::new()?;
    let verified = context
        .init(
            &trust_anchor,
            &pck_crl_cert_chain[0],
            &intermediate_certs,
            |c| c.verify_cert(),
        )
        .map_err(|e| anyhow!(e.to_string()))?;

    if !verified {
        bail!("PCK CRL certificate chain failed to verify");
    }

    // TODO: check next_update() and verify()
    match pck_crl.get_by_cert(&pck_certificates[PCK_LEAF]) {
        CrlStatus::NotRevoked => println!("PCK NotRevoked"),
        CrlStatus::Revoked(r) => println!("PCK Revoked on {:?}", r.revocation_date().to_string()),
        CrlStatus::RemoveFromCrl(r) => {
            println!(
                "PCK Removed from Crl on {:?}",
                r.revocation_date().to_string()
            )
        }
    }

    let pck_der = pck_certificates[PCK_LEAF].to_der()?;
    let parsed_pck = X509Certificate::from_der(&pck_der)?.1.tbs_certificate;

    let value = parsed_pck
        .get_extension_unique(&pck::DCAP_SGX_EXTENSIONS)?
        .ok_or_else(|| anyhow!("SGX Extensions not found in PCK Cert"))?
        .value;

    let parsed = pck::parse_sgx_extensions(value)?;
    let CollateralData { body: f, cert_chain: raw_tcb_cert_chain } = collateral
        .get(CollateralType::TcbInfo(
            &IntelTee::Tdx,
            hex::encode(parsed.fmspc.s).as_str(),
        ))
        .await
        .expect("baz");

    // = Start TCB Status Checks =
    let tcb_cert_chain = X509::stack_from_pem(&raw_tcb_cert_chain.unwrap())?;
    let d: TcbInfoJson = serde_json::from_slice(f.as_slice()).expect("Deserialize");

    if d.tcb_info.fmspc == parsed.fmspc.s {
        println!("FMSCP OK!");
    }

    let bytes = serde_json::to_vec(&d.tcb_info).expect("Serialize to bytes");

    let mut context = X509StoreContext::new()?;
    let verified = context
        .init(
            &trust_anchor,
            &tcb_cert_chain[0],
            &intermediate_certs,
            |c| c.verify_cert(),
        )
        .map_err(|e| anyhow!(e.to_string()))?;

    if !verified {
        bail!("TCB Info certificate chain failed to verify");
    }
    let pub_key = tcb_cert_chain[0]
        .public_key()
        .expect("Get public key from the signing certificate");

    let ec_key = EcKey::try_from(pub_key)?;
    ecdsa_signature_matches(
        &sha256(&bytes),
        &d.signature[..32],
        &d.signature[32..],
        ec_key.as_ref(),
    )
    .map_err(|e| anyhow!("ECDSA signature error: {e}"))
    .and_then(|r| {
        if !r {
            Err(anyhow!("Quote ECDSA signature verification failed."))
        } else {
            println!("TCB Info Signature OK");
            Ok(())
        }
    })?;

    let pck_cpu_svns: [u8; 16] = [
        parsed.tcb.tcbs.comp1.val,
        parsed.tcb.tcbs.comp2.val,
        parsed.tcb.tcbs.comp3.val,
        parsed.tcb.tcbs.comp4.val,
        parsed.tcb.tcbs.comp5.val,
        parsed.tcb.tcbs.comp6.val,
        parsed.tcb.tcbs.comp7.val,
        parsed.tcb.tcbs.comp8.val,
        parsed.tcb.tcbs.comp9.val,
        parsed.tcb.tcbs.comp10.val,
        parsed.tcb.tcbs.comp11.val,
        parsed.tcb.tcbs.comp12.val,
        parsed.tcb.tcbs.comp13.val,
        parsed.tcb.tcbs.comp14.val,
        parsed.tcb.tcbs.comp15.val,
        parsed.tcb.tcbs.comp16.val,
    ];

    let pck_cpu_pcesvn = parsed.tcb.tcbs.pcesvn.val;

    // Go over the sorted collection of TCB Levels retrieved from
    // TCB Info starting from the first item on the list:
    let tcb_level = d
        .tcb_info
        .tcb_levels
        .iter()
        .position(|lvl| get_tcb_status(lvl, &pck_cpu_svns, pck_cpu_pcesvn, Some(qt.tcb_svn())));

    // FAIL on None!
    println!("{:?}", tcb_level);

    // Perform additional TCB status evaluation for TDX module in case TEE TCB
    // SVN at index 1 is greater or equal to 1, otherwise finish the comparison logic.
    // In order to determine TCB status of TDX module, find a matching TDX Module Identity
    // (in tdxModuleIdentities array of TCB Info) with its id set to "TDX_<version>"
    // where <version> matches the value of TEE TCB SVN at index 1. If a matching TDX
    // Module Identity cannot be found, go to step 6, otherwise, for the selected TDX
    // Module Identity go over the sorted collection of TCB Levels starting from the
    // first item on the list and compare its isvsvn value to the TEE TCB SVN at
    // index 0. If TEE TCB SVN at index 0 is greater or equal to its value, read
    // tcbStatus assigned to this TCB level, otherwise move to the next item on TCB
    // levels list.
    let tdx_module_isvsvn = qt.tcb_svn()[0];
    let tdx_module_id = format!("TDX_{}", hex::encode_upper(&qt.tcb_svn()[1..2]));

    // TODO: only if TEE TCB SVN at index is >= 1
    let tcb = d
        .tcb_info
        .tdx_module_identities
        .as_ref()
        .and_then(|mi_ref| {
            mi_ref
                .iter()
                .position(|i| i.id == tdx_module_id)
                .and_then(|p| {
                    mi_ref[p]
                        .tcb_levels
                        .iter()
                        .find(|&level| tdx_module_isvsvn >= level.tcb.isvsvn.unwrap_or(u8::MAX))
                })
        });

    tcb.inspect(|tcb_level| println!("tcb status from level {:?}", tcb_level.tcb_status));

    // = End TCB Status Checks =
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel_dcap::collateral_service::{Tcb, TcbComponent, TcbComponentList, TcbLevel, TcbStatus};
    use chrono::Utc;
    use rstest::rstest;

    fn make_tcb_components(svns: &[u8; 16]) -> TcbComponentList {
        TcbComponentList(std::array::from_fn(|i| TcbComponent {
            svn: svns[i],
            category: None,
            r#type: None,
        }))
    }

    fn make_tcb_level(
        sgx_svns: Option<[u8; 16]>,
        pcesvn: Option<u16>,
        tdx_svns: Option<[u8; 16]>,
    ) -> TcbLevel {
        TcbLevel {
            tcb: Tcb {
                sgxtcbcomponents: sgx_svns.map(|s| make_tcb_components(&s)),
                pcesvn,
                tdxtcbcomponents: tdx_svns.map(|s| make_tcb_components(&s)),
                isvsvn: None,
            },
            tcb_date: Utc::now(),
            tcb_status: TcbStatus::UpToDate,
            advisoryIDs: None,
        }
    }

    // Helper to build SGX-only cert SVNs: all `val` except optionally one override at `idx`
    fn sgx_cert(val: u8, idx: Option<(usize, u8)>) -> [u8; 16] {
        let mut svns = [val; 16];
        if let Some((i, v)) = idx {
            svns[i] = v;
        }
        svns
    }

    // Helper to build TEE TCB SVNs: all `val`, with td_svns[1] = tee_svn1
    fn td_cert(val: u8, tee_svn1: u8, idx: Option<(usize, u8)>) -> [u8; 16] {
        let mut svns = [val; 16];
        svns[1] = tee_svn1;
        if let Some((i, v)) = idx {
            svns[i] = v;
        }
        svns
    }

    #[rstest]
    // SGX SVN checks
    #[case("equal", sgx_cert(4, None), 0, None,  Some([4u8; 16]), Some(0), None,  true)]
    #[case("higher", sgx_cert(5, None), 0, None, Some([4u8; 16]), Some(0), None,  true)]
    #[case("one lower", sgx_cert(4, Some((7, 3))), 0, None, Some([4u8; 16]), Some(0), None, false)]
    // Lexicographic trap: [5,0,...] > [4,255,...] lexicographically, fails element-wise
    #[case("lexico trap", sgx_cert(0, Some((0, 5))), 0, None, Some({let mut r=[0u8;16]; r[0]=4; r[1]=255; r}), Some(0), None, false)]
    // PCESVN checks
    #[case("pcesvn equal", sgx_cert(4, None), 10, None, Some([4u8; 16]), Some(10), None, true)]
    #[case("pcesvn too low", sgx_cert(4, None), 9, None, Some([4u8; 16]), Some(10), None, false)]
    // No sgxtcbcomponents in reference
    #[case("no sgx comps", [0u8; 16], 0, None, None, Some(0), None, false)]
    // TDX: tee_svn1 != 0 → skip indices 0 and 1, compare 2..15
    #[case("tdx equal", sgx_cert(4, None), 0, Some([3u8; 16]), Some([4u8; 16]), Some(0), Some([3u8; 16]), true)]
    #[case("tdx one lower", sgx_cert(4, None), 0, Some({let mut s=[3u8;16]; s[5]=2; s}), Some([4u8; 16]), Some(0), Some([3u8; 16]), false)]
    // TDX: tee_svn1 == 0, compare all 16 indices including 0 and 1
    #[case("tdx skip 0-1", sgx_cert(4, None), 0, Some(td_cert(3, 1, None)), Some([4u8; 16]), Some(0), Some({let mut r=[3u8;16]; r[0]=255; r[1]=255; r}), true)]
    // TDX: missing tdxtcbcomponents in reference
    #[case("tdx no comps", sgx_cert(4, None), 0, Some(td_cert(3, 0, None)), Some([4u8; 16]), Some(0), None, false)]
    fn test_get_tcb_status(
        #[case] _desc: &str,
        #[case] cert_svns: [u8; 16],
        #[case] cert_pcesvn: u16,
        #[case] td_svns: Option<[u8; 16]>,
        #[case] ref_sgx: Option<[u8; 16]>,
        #[case] ref_pcesvn: Option<u16>,
        #[case] ref_tdx: Option<[u8; 16]>,
        #[case] expected: bool,
    ) {
        let lvl = make_tcb_level(ref_sgx, ref_pcesvn, ref_tdx);
        assert_eq!(
            get_tcb_status(&lvl, &cert_svns, cert_pcesvn, td_svns.as_ref().map(|s| s.as_slice())),
            expected,
            "case: {_desc}"
        );
    }
}
