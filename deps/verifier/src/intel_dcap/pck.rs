// Copyright (c) 2026 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

//! Parsing of Intel SGX extensions from PCK (Provisioning Certification Key)
//! certificates. The extensions are DER-encoded under OID 1.2.840.113741.1.13.1
//! and are present in both TDX and SGX PCK certificate chains.
//! See "Intel® SGX PCK Certificate and Certificate Revocation List Profile Specification".

use anyhow::{Context, Result};
use asn1_rs::{oid, DerSequence, Enumerated, FromDer, Oid};
use x509_parser::prelude::*;

pub(crate) const DCAP_SGX_EXTENSIONS: Oid<'static> = oid!(1.2.840 .113741 .1 .13 .1);

#[derive(Debug, PartialEq, DerSequence)]
pub(crate) struct OidAndString<'a> {
    pub(crate) id: Oid<'a>,
    pub(crate) s: &'a [u8],
}

#[derive(Debug, PartialEq, DerSequence)]
pub(crate) struct OidAndInt<'a> {
    pub(crate) id: Oid<'a>,
    pub(crate) val: u8,
}

#[derive(Debug, PartialEq, DerSequence)]
pub(crate) struct OidAndInt16<'a> {
    pub(crate) id: Oid<'a>,
    pub(crate) val: u16,
}

#[derive(Debug, PartialEq, DerSequence)]
pub(crate) struct OidAndEnum<'a> {
    pub(crate) id: Oid<'a>,
    pub(crate) e: Enumerated,
}

#[derive(Debug, PartialEq, DerSequence)]
pub(crate) struct OidAndBool<'a> {
    pub(crate) id: Oid<'a>,
    pub(crate) b: bool,
}

#[derive(Debug, PartialEq, DerSequence)]
pub(crate) struct PlatformConfig<'a> {
    pub(crate) dynamic_platform: OidAndBool<'a>,
    pub(crate) cached_keys: OidAndBool<'a>,
    pub(crate) smt_enabled: OidAndBool<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub(crate) struct ConfigSequence<'a> {
    pub(crate) id: Oid<'a>,
    pub(crate) configs: PlatformConfig<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub(crate) struct Tcbs<'a> {
    pub(crate) comp1: OidAndInt<'a>,
    pub(crate) comp2: OidAndInt<'a>,
    pub(crate) comp3: OidAndInt<'a>,
    pub(crate) comp4: OidAndInt<'a>,
    pub(crate) comp5: OidAndInt<'a>,
    pub(crate) comp6: OidAndInt<'a>,
    pub(crate) comp7: OidAndInt<'a>,
    pub(crate) comp8: OidAndInt<'a>,
    pub(crate) comp9: OidAndInt<'a>,
    pub(crate) comp10: OidAndInt<'a>,
    pub(crate) comp11: OidAndInt<'a>,
    pub(crate) comp12: OidAndInt<'a>,
    pub(crate) comp13: OidAndInt<'a>,
    pub(crate) comp14: OidAndInt<'a>,
    pub(crate) comp15: OidAndInt<'a>,
    pub(crate) comp16: OidAndInt<'a>,
    pub(crate) pcesvn: OidAndInt16<'a>,
    pub(crate) cpusvn: OidAndString<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub(crate) struct TcbSequence<'a> {
    pub(crate) id: Oid<'a>,
    pub(crate) tcbs: Tcbs<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub(crate) struct SgxExtension<'a> {
    pub(crate) ppid: OidAndString<'a>,
    pub(crate) tcb: TcbSequence<'a>,
    pub(crate) pceid: OidAndString<'a>,
    pub(crate) fmspc: OidAndString<'a>,
    pub(crate) sgxtype: OidAndEnum<'a>,
    pub(crate) platform_instance: OidAndString<'a>,
    pub(crate) configuration: ConfigSequence<'a>,
}

/// Parse the DER-encoded SGX extensions value from a PCK certificate extension.
/// The caller is responsible for extracting the raw extension bytes (OID 1.2.840.113741.1.13.1).
pub(crate) fn parse_sgx_extensions(value: &[u8]) -> Result<SgxExtension<'_>> {
    SgxExtension::from_der(value)
        .map(|(_, ext)| ext)
        .map_err(|e| anyhow::anyhow!("Failed to parse SGX extension DER: {e}"))
}

/// Parse all PEM-encoded certificates from a PCK certificate chain.
/// The Intel cert chain ordering is leaf (index 0), intermediate CA, root CA.
pub(crate) fn parse_pck_pem_certs(pem_certs: &[u8]) -> Result<Vec<Pem>> {
    Pem::iter_from_buffer(pem_certs)
        .collect::<Result<Vec<Pem>, _>>()
        .context("failed to parse PCK PEM certificate chain")
}

/// Extract the `platform_instance_id` from an already-parsed PCK leaf certificate.
/// Returns `Ok(None)` if the SGX extensions OID is absent (Processor CA-signed certs).
/// The `platform_instance` field is only present in Platform CA-signed PCK certs.
pub(crate) fn platform_instance_id_from_pck_leaf_cert(
    cert: &X509Certificate,
) -> Result<Option<[u8; 16]>> {
    let ext = cert
        .tbs_certificate
        .get_extension_unique(&DCAP_SGX_EXTENSIONS)
        .context("failed to look up SGX extensions OID")?;

    let ext_value = match ext {
        Some(e) => e.value,
        None => return Ok(None),
    };

    let (_, parsed) =
        SgxExtension::from_der(ext_value).context("failed to parse SGX extension DER")?;

    let bytes: [u8; 16] = parsed
        .platform_instance
        .s
        .try_into()
        .context("platform_instance is not 16 bytes")?;

    // The GUID is stored little-endian in the OCTET STRING; convert to big-endian.
    Ok(Some(u128::from_le_bytes(bytes).to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{parse_pck_pem_certs, platform_instance_id_from_pck_leaf_cert};
    use crate::tdx::quote::{parse_tdx_quote, parse_tdx_quote_certification};

    #[test]
    fn parse_platform_instance_id() {
        let quote_bin = std::fs::read("./test_data/tdx_quote_4.dat").expect("read quote failed");
        let quote = parse_tdx_quote(&quote_bin).expect("parse quote");
        let pck_certs_pem = parse_tdx_quote_certification(&quote_bin, &quote)
            .expect("parse cert chain")
            .qe_certification_data
            .certificates;

        let certs = parse_pck_pem_certs(&pck_certs_pem).expect("parse PEM certs");
        let leaf = certs[0].parse_x509().expect("parse leaf cert");

        let piid = platform_instance_id_from_pck_leaf_cert(&leaf)
            .expect("extract platform_instance_id")
            .expect("platform_instance_id not present");

        assert_eq!(hex::encode(piid), "82548d228d94d5e204a95b354dc61a02");
    }
}
