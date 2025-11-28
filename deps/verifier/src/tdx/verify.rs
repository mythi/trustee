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
    pcesvn: OidAndInt<'ext>,
    cpusvn: OidAndString<'ext>,
}

fn tcb_comp_to_bytes(seq: &Tcbs) -> [u8; 16] {
    [
        seq.comp1.val,
        seq.comp2.val,
        seq.comp3.val,
        seq.comp4.val,
        seq.comp5.val,
        seq.comp6.val,
        seq.comp7.val,
        seq.comp8.val,
        seq.comp9.val,
        seq.comp10.val,
        seq.comp11.val,
        seq.comp12.val,
        seq.comp13.val,
        seq.comp14.val,
        seq.comp15.val,
        seq.comp16.val,
    ]
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

struct CollateralCertificates {
    pck_crl_issuer_intermediate_certificate: X509,
    pck_crl_issuer_root_certificate: X509,
    pck_crl: X509Crl,
    tcb_info_issuer_intermediate_certificate: X509,
    tcb_info_issuer_root_certificate: X509,
    qe_identity_issuer_intermediate_certificate: X509,
    qe_identity_issuer_root_certificate: X509,
    root_ca_crl: X509Crl,
}

const PCK_LEAF: usize = 0;
const INTERMEDIATE_CA: usize = 1;
const ROOT_CA: usize = 2;

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
    println!("tcb {:?}", tcb_comp_to_bytes(&parsed.tcb.tcbs));
    //let reversed: Vec<u8> = parsed.ppid.s.iter().rev().cloned().collect();

    let _pcs_chain = X509::stack_from_pem(&bar.unwrap())?;
    let d: TcbInfoJson = serde_json::from_slice(f.as_slice()).expect("Deserialize");
    println!("{}", d.tcb_info.tcb_levels.len());

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
