use crate::intel_dcap::collateral_service::*;
use crate::sgx::types::*;
use crate::tdx::quote::QuoteSignatureData;
use anyhow::{anyhow, bail};
use asn1_rs::{oid, DerSequence, Enumerated, FromDer, Oid};
use openssl::bn::BigNum;
use openssl::nid::Nid;
use openssl::sha::{sha256, Sha256};
use openssl::stack::Stack;
use openssl::x509::{
    store::X509Store, store::X509StoreBuilder, X509Crl, X509StoreContext, X509VerifyResult, X509,
};
use openssl::{ec::EcGroup, ec::EcKey, ecdsa::EcdsaSig};
use scroll::Pread;
use std::sync::LazyLock;
use x509_parser::prelude::X509Certificate;

static INTEL_PCS_ROOT_CA: LazyLock<X509Store> = LazyLock::new(|| {
    let trust_anchor = X509::from_pem(include_bytes!(
        "Intel_SGX_Provisioning_Certification_RootCA.pem"
    ))
    .unwrap();
    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(trust_anchor).unwrap();
    builder.build()
});

const DCAP_SGX_EXTENSIONS: Oid<'static> = oid!(1.2.840 .113741 .1 .13 .1);

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndString<'ext> {
    id: Oid<'ext>,
    s: &'ext [u8],
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndInt<'ext> {
    id: Oid<'ext>,
    val: u8,
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndInt16<'ext> {
    id: Oid<'ext>,
    val: u16,
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndEnum<'ext> {
    id: Oid<'ext>,
    e: Enumerated,
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndBool<'ext> {
    id: Oid<'ext>,
    b: bool,
}

#[derive(Debug, PartialEq, DerSequence)]
struct PlatformConfig<'ext> {
    dynamic_platform: OidAndBool<'ext>,
    cached_keys: OidAndBool<'ext>,
    smt_enabled: OidAndBool<'ext>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct ConfigSequence<'ext> {
    id: Oid<'ext>,
    configs: PlatformConfig<'ext>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct Tcbs<'ext> {
    comp1: OidAndInt<'ext>,
    comp2: OidAndInt<'ext>,
    comp3: OidAndInt<'ext>,
    comp4: OidAndInt<'ext>,
    comp5: OidAndInt<'ext>,
    comp6: OidAndInt<'ext>,
    comp7: OidAndInt<'ext>,
    comp8: OidAndInt<'ext>,
    comp9: OidAndInt<'ext>,
    comp10: OidAndInt<'ext>,
    comp11: OidAndInt<'ext>,
    comp12: OidAndInt<'ext>,
    comp13: OidAndInt<'ext>,
    comp14: OidAndInt<'ext>,
    comp15: OidAndInt<'ext>,
    comp16: OidAndInt<'ext>,
    pcesvn: OidAndInt16<'ext>,
    cpusvn: OidAndString<'ext>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct TcbSequence<'ext> {
    id: Oid<'ext>,
    tcbs: Tcbs<'ext>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct SgxExtension<'ext> {
    ppid: OidAndString<'ext>,
    tcb: TcbSequence<'ext>,
    pceid: OidAndString<'ext>,
    fmspc: OidAndString<'ext>,
    sgxtype: OidAndEnum<'ext>,
    platform_instance: OidAndString<'ext>,
    configuration: ConfigSequence<'ext>,
}

// struct CollateralCertificates {
//     pck_crl_issuer_intermediate_certificate: X509,
//     pck_crl_issuer_root_certificate: X509,
//     pck_crl: X509Crl,
//     tcb_info_issuer_intermediate_certificate: X509,
//     tcb_info_issuer_root_certificate: X509,
//     qe_identity_issuer_intermediate_certificate: X509,
//     qe_identity_issuer_root_certificate: X509,
//     root_ca_crl: X509Crl,
// }

// const PCK_LEAF: usize = 0;
// const INTERMEDIATE_CA: usize = 1;
// const ROOT_CA: usize = 2;

fn get_tcb_status(ref_tcb: &TcbLevel, pck_cert_tcb: &Tcbs, td_svns: Option<&[u8]>) -> bool {
    let pck_cpu_svns: [u8; 16] = [
        pck_cert_tcb.comp1.val,
        pck_cert_tcb.comp2.val,
        pck_cert_tcb.comp3.val,
        pck_cert_tcb.comp4.val,
        pck_cert_tcb.comp5.val,
        pck_cert_tcb.comp6.val,
        pck_cert_tcb.comp7.val,
        pck_cert_tcb.comp8.val,
        pck_cert_tcb.comp9.val,
        pck_cert_tcb.comp10.val,
        pck_cert_tcb.comp11.val,
        pck_cert_tcb.comp12.val,
        pck_cert_tcb.comp13.val,
        pck_cert_tcb.comp14.val,
        pck_cert_tcb.comp15.val,
        pck_cert_tcb.comp16.val,
    ];

    // Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate
    // (from 01 to 16) with the corresponding values of SVNs in sgxtcbcomponents
    // array of TCB Level. If all SGX TCB Comp SVNs in the certificate are greater
    // or equal to the corresponding values in TCB Level, compare PCESVN value
    // retrieved from the SGX PCK certificate is greater or equal to the corresponding
    // value in the TCB Level. If both are true, move on. Otherwise, return false.
    if ref_tcb
        .tcb
        .sgxtcbcomponents
        .as_ref()
        .map(|r| r.0.iter().map(|c| c.svn).collect::<Vec<u8>>())
        .inspect(|d| println!("sgxtcbcomponents {d:?}"))
        .map(|ref_cpu_svns| {
            pck_cpu_svns.len() == ref_cpu_svns.len()
                && pck_cpu_svns.as_ref() >= ref_cpu_svns.as_slice()
                && pck_cert_tcb.pcesvn.val >= ref_tcb.tcb.pcesvn.unwrap_or(u16::MAX)
        })
        .is_none_or(|t| !t)
    {
        // return false if None or TCB check failed
        return false;
    }

    // Return true if no TEE TCB SVN was provided (case SGX) or
    // then the TEE TCB SVN comparison with tdxtcbcomponents was successful
    td_svns
        .and_then(|tds| {
            let mut idx = 0;

            if tds[1] > 0 {
                idx = 2;
            }

            ref_tcb
                .tcb
                .tdxtcbcomponents
                .as_ref()
                .map(|r| r.0.iter().map(|c| c.svn).collect::<Vec<u8>>())
                .inspect(|d| println!("tdxtcbcomponents {d:?}"))
                .map(|ref_td_svns| {
                    tds[idx..].len() == ref_td_svns[idx..].len() && tds[idx..] >= ref_td_svns[idx..]
                })
                .or(Some(false))
        })
        .is_none_or(|t| t)
}

pub async fn dcap_verify(
    raw_quote: &[u8],
    qe: &QuoteSignatureData,
    collateral: &impl CollateralService,
) -> anyhow::Result<bool> {
    let x = BigNum::from_slice(&qe.quote_signature.pkey_x_coord)?;
    let y = BigNum::from_slice(&qe.quote_signature.pkey_y_coord)?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let pub_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;

    let r = BigNum::from_slice(&qe.quote_signature.sig_r)?;
    let s = BigNum::from_slice(&qe.quote_signature.sig_s)?;
    let ecdsa_sig = EcdsaSig::from_private_components(r, s)?;

    ecdsa_sig
        .verify(&sha256(raw_quote), &pub_key)
        .map_err(|e| anyhow!("Error in ECDSA Signature verification: {}.", e))
        .and_then(|result| {
            if !result {
                Err(anyhow!("Quote ECDSA signature verification failed."))
            } else {
                println!("OK!");
                Ok(())
            }
        })?;

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

    let pck_certs = X509::stack_from_pem(&qe.qe_certification_data.certificates)?;
    let public_key = pck_certs[0].public_key()?;
    let ec_key = EcKey::try_from(public_key)?;

    let r = BigNum::from_slice(&qe.qe_certification_data.qe_report.sig_r)?;
    let s = BigNum::from_slice(&qe.qe_certification_data.qe_report.sig_s)?;
    let ecdsa_sig = EcdsaSig::from_private_components(r, s)?;
    let res = ecdsa_sig.verify(&sha256(&qe.qe_certification_data.qe_report.report), &ec_key)?;
    println!("{res}");

    if pck_certs[2].issued(&pck_certs[2]) != X509VerifyResult::OK {
        println!("{:?}", pck_certs[2]);
    }

    if pck_certs[2].issued(&pck_certs[1]) != X509VerifyResult::OK {
        println!("{:?}", pck_certs[1]);
    }

    if pck_certs[1].issued(&pck_certs[0]) != X509VerifyResult::OK {
        println!("{:?}", pck_certs[0]);
    }

    let pck_der = pck_certs[0].to_der()?;
    let parsed_pck = X509Certificate::from_der(&pck_der)?.1.tbs_certificate;

    let value = parsed_pck
        .get_extension_unique(&DCAP_SGX_EXTENSIONS)?
        .ok_or_else(|| anyhow!("SGX Extensions not found in PCK Cert"))?
        .value;

    let (_, parsed) = SgxExtension::from_der(value).expect("Failed to parse");
    let (f, bar) = collateral
        .get(CollateralType::TcbInfo(
            &IntelTee::Tdx,
            hex::encode(parsed.fmspc.s).as_str(),
        ))
        .await
        .expect("baz");
    //let reversed: Vec<u8> = parsed.ppid.s.iter().rev().cloned().collect();

    let _pcs_chain = X509::stack_from_pem(&bar.unwrap())?;
    let d: TcbInfoJson = serde_json::from_slice(f.as_slice()).expect("Deserialize");

    // TODO: pass TEE TCB SVN
    let tee_tcb_svn: [u8; 16] = [5, 3, 13, 2, 3, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0];

    // Go over the sorted collection of TCB Levels retrieved from
    // TCB Info starting from the first item on the list:
    let tcb_level = d
        .tcb_info
        .tcb_levels
        .iter()
        .position(|lvl| get_tcb_status(lvl, &parsed.tcb.tcbs, Some(&tee_tcb_svn)));

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
    let tcb = d
        .tcb_info
        .tdx_module_identities
        .as_ref()
        .and_then(|mi_ref| {
            mi_ref
                .iter()
                .position(|i| i.id == format!("TDX_{}", hex::encode_upper(&tee_tcb_svn[1..2])))
                .and_then(|p| {
                    mi_ref[p]
                        .tcb_levels
                        .iter()
                        .find(|&level| tee_tcb_svn[1] >= level.tcb.isvsvn.unwrap_or(u8::MAX))
                })
        });
    println!("FMSPC {:?}", hex::encode(parsed.fmspc.s));
    println!("tcb status from level {:?}", tcb.unwrap().tcb_status);

    let mut intermediate_certs = Stack::<X509>::new()?;
    intermediate_certs.push(pck_certs[1].clone())?;
    let mut context = X509StoreContext::new()?;
    let verified = context
        .init(
            &INTEL_PCS_ROOT_CA,
            &pck_certs[0],
            &intermediate_certs,
            |c| c.verify_cert(),
        )
        .map_err(|e| anyhow!(e.to_string()))?;

    if !verified {
        bail!("Report certificate chain failed to verify");
    }

    Ok(true)
}
