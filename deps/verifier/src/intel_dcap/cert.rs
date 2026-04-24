// Copyright (c) 2026 Confidential Containers Project Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Certificate/CRL parsing and verification used by DCAP collateral
//! validation, built on `x509-parser`.
//!
//! Unlike OpenSSL's `X509StoreContext::verify_cert`, this does not build an
//! arbitrary certificate path: DCAP's chains have a fixed, known shape
//! (leaf/intermediate/root, or signer/root issuer chains), so [`Cert::validate`]
//! verifies that fixed shape directly — pairwise issuer-signature checks
//! anchored at a pinned trust root — which is also how Intel's own QVL
//! reference implementation does it (`CommonVerifier::checkSignature`),
//! rather than through automatic path discovery.
//!
//! Every trust decision must be anchored to the pinned root cert or to a
//! cert that itself was already verified against that root — never to an
//! untrusted cert's own self-declared key.

#[cfg(feature = "ring")]
use crate::intel_dcap::crypto;
use crate::intel_dcap::pck::{self, PlatformInfo};
use anyhow::{Context, Result, anyhow, bail};
use asn1_rs::{Oid, oid};
use chrono::{DateTime, Utc};
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA256;
use x509_parser::prelude::*;

const CRL_DISTRIBUTION_POINTS: Oid<'static> = oid!(2.5.29.31);

/// DCAP PKI certificate role, each with a fixed, spec-defined Common Name
/// ("Intel® SGX PCK Certificate and Certificate Revocation List Profile
/// Specification" §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertRole {
    RootCa,
    PckPlatformCa,
    PckProcessorCa,
    PckLeaf,
    TcbSigning,
}

impl CertRole {
    pub(crate) fn common_name(&self) -> &'static str {
        match self {
            CertRole::RootCa => "Intel SGX Root CA",
            CertRole::PckPlatformCa => "Intel SGX PCK Platform CA",
            CertRole::PckProcessorCa => "Intel SGX PCK Processor CA",
            CertRole::PckLeaf => "Intel SGX PCK Certificate",
            CertRole::TcbSigning => "Intel SGX TCB Signing",
        }
    }
}

/// The subject Common Name of an already-parsed certificate, if present and
/// UTF-8 — zero-copy, borrowed straight from the DER bytes. Split out from
/// [`Cert::common_name`] for callers (like [`Cert::validate`]) that already
/// hold a parsed certificate and don't want a second parse just to allocate
/// a copy of a string they're about to compare and discard.
fn common_name_of<'a>(cert: &'a X509Certificate<'a>) -> Option<&'a str> {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
}

/// The first CRL Distribution Point URL of an already-parsed certificate, if
/// the extension is present.
fn crl_distribution_point_of(cert: &X509Certificate<'_>) -> Option<String> {
    let ext = cert.get_extension_unique(&CRL_DISTRIBUTION_POINTS).ok()??;
    let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() else {
        return None;
    };
    for point in points.iter() {
        if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
            for name in names {
                if let GeneralName::URI(uri) = name {
                    return Some(uri.to_string());
                }
            }
        }
    }
    None
}

/// A parsed certificate. Everything except the issuer-signature check is
/// extracted once at construction: none of these fields change, so
/// re-parsing the DER on every accessor call redid the same work for no
/// benefit. The raw DER is kept only for [`Cert::validate`]
/// (whose signature check needs the exact to-be-signed bytes and the
/// signature from a live parsed view) and [`Cert::platform_info`] (which needs a live view to look up the SGX
/// extension; not cached since `is_platform_ca` isn't known until the PCK
/// intermediate's own CN has been classified, after this cert is constructed).
pub(crate) struct Cert {
    der: Vec<u8>,
    common_name: Option<String>,
    is_v3: bool,
    is_ecdsa_p256: bool,
    not_before: i64,
    not_after: i64,
    serial_number: Vec<u8>,
    /// Uncompressed SEC1 P-256 point (`0x04 || X || Y`), if the key is one.
    ec_public_key: Option<[u8; 65]>,
    crl_distribution_point: Option<String>,
}

impl Cert {
    /// Parses every certificate in a PEM-encoded chain, in file order, and
    /// checks it's exactly `expected_len` certificates long — DCAP's chains
    /// always have a fixed, known shape (see the module doc), so callers
    /// always know this upfront rather than needing to check it themselves.
    pub(crate) fn chain_from_pem(pem: &[u8], expected_len: usize) -> Result<Vec<Self>> {
        let certs: Vec<Self> = Pem::iter_from_buffer(pem)
            .map(|pem| {
                let pem = pem.context("failed to parse PEM certificate")?;
                Self::from_der(pem.contents)
            })
            .collect::<Result<_>>()?;
        if certs.len() != expected_len {
            bail!(
                "expected exactly {expected_len} certificate(s) in PEM chain, got {}",
                certs.len()
            );
        }
        Ok(certs)
    }

    fn from_der(der: Vec<u8>) -> Result<Self> {
        let (_, cert) =
            parse_x509_certificate(&der).context("failed to parse X.509 certificate")?;

        let ec_public_key =
            <[u8; 65]>::try_from(cert.public_key().subject_public_key.data.as_ref())
                .ok()
                .filter(|point| point[0] == 0x04);

        let validity = cert.validity();

        Ok(Self {
            common_name: common_name_of(&cert).map(str::to_string),
            is_v3: cert.version() == X509Version::V3,
            is_ecdsa_p256: cert.signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA256,
            not_before: validity.not_before.timestamp(),
            not_after: validity.not_after.timestamp(),
            serial_number: cert.raw_serial().to_vec(),
            ec_public_key,
            crl_distribution_point: crl_distribution_point_of(&cert),
            der,
        })
    }

    fn parse(&self) -> Result<X509Certificate<'_>> {
        let (_, cert) =
            parse_x509_certificate(&self.der).context("failed to parse X.509 certificate")?;
        Ok(cert)
    }

    /// The subject Common Name, if present and UTF-8. Prefer
    /// [`Cert::is_common_name`] for a yes/no test against known candidates;
    /// this is for the rare case of needing the value itself, e.g. reporting
    /// an unexpected one in an error.
    pub(crate) fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }

    /// `true` if this cert's subject Common Name is exactly `expected`.
    pub(crate) fn is_common_name(&self, expected: &str) -> bool {
        self.common_name.as_deref() == Some(expected)
    }

    /// Certificate validity window, as Unix timestamps.
    pub(crate) fn validity(&self) -> (i64, i64) {
        (self.not_before, self.not_after)
    }

    /// This cert's public key as an uncompressed SEC1 P-256 point.
    pub(crate) fn public_key(&self) -> Result<&[u8; 65]> {
        self.ec_public_key
            .as_ref()
            .context("EC public key point is not 65 bytes (uncompressed SEC1)")
    }

    /// sha384 of this cert's raw EC public key point, for the `root_key_id` claim.
    #[cfg(feature = "ring")]
    pub(crate) fn key_id(&self) -> Result<[u8; 48]> {
        Ok(crypto::sha384(self.public_key()?))
    }

    /// The first CRL Distribution Point URL, if the extension is present.
    pub(crate) fn crl_distribution_point(&self) -> Option<&str> {
        self.crl_distribution_point.as_deref()
    }

    /// Raw (big-endian) serial number bytes, for revocation lookups.
    pub(crate) fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }

    /// Extracts this (PCK leaf) cert's SGX extension — FMSPC, PCEID, TCB
    /// components, etc. `is_platform_ca` should come from the PCK
    /// intermediate CA's already-validated [`CertRole`], and is cross-checked
    /// against this cert's own extension shape — see [`pck::extract_platform_info`].
    pub(crate) fn platform_info(&self, is_platform_ca: bool) -> Result<PlatformInfo> {
        pck::extract_platform_info(&self.parse()?, is_platform_ca)
    }

    /// X.509 v3, ECDSA-P256-SHA256, the Common Name for `role`, and a valid
    /// signature by `issuer_key` (the issuer cert's key, or the trust
    /// anchor's) — every property a DCAP PKI certificate must have, checked
    /// together so no chain hop can skip one by accident.
    ///
    /// Does not check expiration; that's tracked separately via [`Validity`]
    /// and is non-fatal (matches upstream DCAP QVL/QvE semantics).
    #[cfg(feature = "ring")]
    pub(crate) fn validate(&self, role: CertRole, issuer_key: &[u8; 65]) -> Result<()> {
        if !self.is_v3 {
            bail!("{role:?} certificate is not X.509 v3");
        }
        if !self.is_ecdsa_p256 {
            bail!("{role:?} certificate is not signed with ECDSA-P256-SHA256");
        }
        if self.common_name.as_deref() != Some(role.common_name()) {
            bail!(
                "{role:?} certificate has unexpected Common Name, expected \"{}\", got {:?}",
                role.common_name(),
                self.common_name,
            );
        }

        let cert = self.parse()?;
        if !crypto::ecdsa_p256_verify_der(
            cert.tbs_certificate.as_ref(),
            &cert.signature_value.data,
            issuer_key,
        ) {
            bail!("{role:?} certificate signature verification failed");
        }
        Ok(())
    }

    /// Raw-bytes ECDSA-P256-SHA256 signature check against *this* cert's own
    /// public key — for signatures over data that isn't itself a
    /// certificate (QE Report, QE Identity, TCB Info).
    #[cfg(feature = "ring")]
    pub(crate) fn verify_message(
        &self,
        message: &[u8],
        sig_r: &[u8],
        sig_s: &[u8],
    ) -> Result<bool> {
        let point = self.public_key()?;
        let x: &[u8; 32] = point[1..33].try_into().expect("32-byte X coordinate");
        let y: &[u8; 32] = point[33..].try_into().expect("32-byte Y coordinate");
        let to_array = |s: &[u8]| -> Result<[u8; 32]> {
            s.try_into()
                .map_err(|_| anyhow!("ECDSA signature component is not 32 bytes"))
        };
        crypto::ecdsa_p256_verify(message, &to_array(sig_r)?, &to_array(sig_s)?, x, y)
    }
}

/// A parsed CRL, borrowing the DER it was parsed from. It's parsed exactly
/// once and the parsed view is kept for every check: `x509-parser` eagerly
/// builds a `Vec` of every revoked-certificate entry on each parse (it's not
/// a lazy view over the DER), and a production PCK CRL can carry many
/// thousands of entries.
///
/// Revocation is checked by scanning that list for the one serial number
/// each DCAP CRL is ever asked about (the PCK intermediate CA for the Root CA
/// CRL, the PCK leaf for the PCK CRL), rather than first copying every
/// entry's serial into a lookup set, which cost one heap allocation per
/// revoked entry for a single lookup.
pub(crate) struct Crl<'a> {
    crl: CertificateRevocationList<'a>,
}

impl<'a> Crl<'a> {
    pub(crate) fn from_der(der: &'a [u8]) -> Result<Self> {
        let (_, crl) = parse_x509_crl(der).context("failed to parse X.509 CRL")?;
        Ok(Self { crl })
    }

    /// `true` if this CRL is signed with ECDSA-P256-SHA256 by `issuer_key`.
    #[cfg(feature = "ring")]
    pub(crate) fn is_issued_by(&self, issuer_key: &[u8; 65]) -> bool {
        self.crl.signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA256
            && crypto::ecdsa_p256_verify_der(
                self.crl.tbs_cert_list.as_ref(),
                &self.crl.signature_value.data,
                issuer_key,
            )
    }

    /// `nextUpdate` as a Unix timestamp, if present.
    pub(crate) fn next_update(&self) -> Option<i64> {
        self.crl.next_update().map(|t| t.timestamp())
    }

    /// `true` if a certificate with the given raw (big-endian) serial number
    /// bytes appears in this CRL's revoked-certificate list.
    pub(crate) fn is_revoked(&self, serial: &[u8]) -> bool {
        self.crl
            .iter_revoked_certificates()
            .any(|revoked| revoked.raw_serial() == serial)
    }

    /// The CRL Number extension value.
    pub(crate) fn crl_number(&self) -> Result<u32> {
        self.crl
            .crl_number()
            .context("CRL is missing the CRL Number extension")?
            .try_into()
            .map_err(|_| anyhow!("CRL Number does not fit in a u32"))
    }
}

/// Aggregates the tightest validity window (earliest/latest issue date,
/// earliest expiration date) across every cert/CRL/collateral item observed
/// during verification.
///
/// It's collected without reference to the current time: expiry is decided
/// against `now` only by [`Validity::expired`], so dates collected once from
/// collateral can be checked again for every quote appraised against it.
#[derive(Clone, Copy)]
pub(crate) struct Validity {
    earliest_not_before: i64,
    latest_not_before: i64,
    earliest_not_after: i64,
    /// Earliest CRL `nextUpdate`. A passed one makes the collateral expired,
    /// but it isn't reported as the earliest expiration date.
    earliest_crl_next_update: i64,
}

impl Validity {
    pub(crate) fn new() -> Self {
        Self {
            earliest_not_before: i64::MAX,
            latest_not_before: i64::MIN,
            earliest_not_after: i64::MAX,
            earliest_crl_next_update: i64::MAX,
        }
    }

    pub(crate) fn observe_cert(&mut self, cert: &Cert) {
        let (not_before, not_after) = cert.validity();
        self.earliest_not_before = self.earliest_not_before.min(not_before);
        self.latest_not_before = self.latest_not_before.max(not_before);
        self.earliest_not_after = self.earliest_not_after.min(not_after);
    }

    /// A CRL without `nextUpdate` never expires.
    pub(crate) fn observe_crl(&mut self, crl: &Crl<'_>) {
        if let Some(next_update) = crl.next_update() {
            self.earliest_crl_next_update = self.earliest_crl_next_update.min(next_update);
        }
    }

    /// Folds in a bare deadline (e.g. a `nextUpdate` field on signed JSON
    /// collateral, which has no matching `not_before`).
    pub(crate) fn observe_deadline(&mut self, deadline: &DateTime<Utc>) {
        self.earliest_not_after = self.earliest_not_after.min(deadline.timestamp());
    }

    /// Folds in everything `other` observed.
    pub(crate) fn merge(&mut self, other: &Validity) {
        self.earliest_not_before = self.earliest_not_before.min(other.earliest_not_before);
        self.latest_not_before = self.latest_not_before.max(other.latest_not_before);
        self.earliest_not_after = self.earliest_not_after.min(other.earliest_not_after);
        self.earliest_crl_next_update = self
            .earliest_crl_next_update
            .min(other.earliest_crl_next_update);
    }

    /// `true` if anything observed has expired by `now`.
    pub(crate) fn expired(&self, now: &DateTime<Utc>) -> bool {
        self.earliest_not_after.min(self.earliest_crl_next_update) < now.timestamp()
    }

    pub(crate) fn earliest_issue_date(&self) -> i64 {
        self.earliest_not_before
    }

    pub(crate) fn latest_issue_date(&self) -> i64 {
        self.latest_not_before
    }

    pub(crate) fn earliest_expiration_date(&self) -> i64 {
        self.earliest_not_after
    }
}
