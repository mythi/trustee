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
use anyhow::{anyhow, bail, Context, Result};
use asn1_rs::{oid, Oid};
use chrono::{DateTime, Utc};
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA256;
use x509_parser::prelude::*;

const CRL_DISTRIBUTION_POINTS: Oid<'static> = oid!(2.5.29 .31);

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
/// extracted once at construction — same reasoning as [`Crl`]: none of these
/// fields change, so re-parsing the DER on every accessor call redid the same
/// work for no benefit. The raw DER is kept only for [`Cert::validate`]
/// (whose signature check needs a live parsed view of both this cert and its
/// issuer, to call `x509-parser`'s own `verify_signature`) and
/// [`Cert::platform_info`] (which needs a live view to look up the SGX
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
    ec_public_key_xy: Option<([u8; 32], [u8; 32])>,
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

        let point = cert.public_key().subject_public_key.data.as_ref();
        let ec_public_key_xy = (point.len() == 65 && point[0] == 0x04).then(|| {
            let x: [u8; 32] = point[1..33].try_into().expect("checked len");
            let y: [u8; 32] = point[33..65].try_into().expect("checked len");
            (x, y)
        });

        let validity = cert.validity();

        Ok(Self {
            common_name: common_name_of(&cert).map(str::to_string),
            is_v3: cert.version() == X509Version::V3,
            is_ecdsa_p256: cert.signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA256,
            not_before: validity.not_before.timestamp(),
            not_after: validity.not_after.timestamp(),
            serial_number: cert.raw_serial().to_vec(),
            ec_public_key_xy,
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
    pub(crate) fn common_name(&self) -> Option<String> {
        self.common_name.clone()
    }

    /// `true` if this cert's subject Common Name is exactly `expected`.
    pub(crate) fn is_common_name(&self, expected: &str) -> bool {
        self.common_name.as_deref() == Some(expected)
    }

    /// Certificate validity window, as Unix timestamps.
    pub(crate) fn validity(&self) -> (i64, i64) {
        (self.not_before, self.not_after)
    }

    pub(crate) fn is_expired(&self, now: &DateTime<Utc>) -> bool {
        self.not_after < now.timestamp()
    }

    /// Raw uncompressed EC public key point, split into affine `x`/`y` (32
    /// bytes each), for [`Cert::verify_message`]/`crypto::ecdsa_p256_verify`.
    pub(crate) fn ec_public_key_xy(&self) -> Result<([u8; 32], [u8; 32])> {
        self.ec_public_key_xy
            .context("EC public key point is not 65 bytes (uncompressed SEC1)")
    }

    /// sha384 of this cert's raw EC public key point, for the `root_key_id` claim.
    #[cfg(feature = "ring")]
    pub(crate) fn key_id(&self) -> Result<[u8; 48]> {
        let (x, y) = self.ec_public_key_xy()?;
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&x);
        point[33..65].copy_from_slice(&y);
        Ok(crypto::sha384(&point))
    }

    /// The first CRL Distribution Point URL, if the extension is present.
    pub(crate) fn crl_distribution_point(&self) -> Option<String> {
        self.crl_distribution_point.clone()
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
    /// signature from `issuer` — every property a DCAP PKI certificate must
    /// have, checked together so no chain hop can skip one by accident.
    ///
    /// Does not check expiration; that's tracked separately via [`Validity`]
    /// and is non-fatal (matches upstream DCAP QVL/QvE semantics).
    pub(crate) fn validate(&self, role: CertRole, issuer: &Cert) -> Result<()> {
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
        let issuer_cert = issuer.parse()?;
        cert.verify_signature(Some(issuer_cert.public_key()))
            .map_err(|e| anyhow!("{role:?} certificate signature verification failed: {e}"))
    }

    /// Raw-bytes ECDSA-P256-SHA256 signature check against *this* cert's own
    /// public key — for signatures over data that isn't itself a
    /// certificate (QE Report, QE Identity, TCB Info).
    #[cfg(feature = "ring")]
    pub(crate) fn verify_message(&self, message: &[u8], sig_r: &[u8], sig_s: &[u8]) -> Result<bool> {
        let (x, y) = self.ec_public_key_xy()?;
        let to_array = |s: &[u8]| -> Result<[u8; 32]> {
            s.try_into()
                .map_err(|_| anyhow!("ECDSA signature component is not 32 bytes"))
        };
        crypto::ecdsa_p256_verify(message, &to_array(sig_r)?, &to_array(sig_s)?, &x, &y)
    }
}

/// A parsed CRL. Unlike [`Cert`], everything except the issuer-signature
/// check is extracted once at construction: `x509-parser` eagerly builds a
/// `Vec` of every revoked-certificate entry on each parse (it's not a lazy
/// view over the DER), and a production PCK CRL can carry many thousands of
/// entries, so re-parsing per accessor call would repeatedly rebuild that
/// whole list. The raw DER is kept only for [`Crl::is_issued_by`], which
/// needs a live parsed view to call `x509-parser`'s own `verify_signature`.
#[derive(Debug)]
pub(crate) struct Crl {
    der: Vec<u8>,
    next_update: Option<i64>,
    revoked_serials: std::collections::HashSet<Vec<u8>>,
    crl_number: std::result::Result<u32, String>,
}

impl Crl {
    pub(crate) fn from_der(der: &[u8]) -> Result<Self> {
        let (_, crl) = parse_x509_crl(der).context("failed to parse X.509 CRL")?;
        let revoked_serials = crl
            .iter_revoked_certificates()
            .map(|revoked| revoked.raw_serial().to_vec())
            .collect();
        let crl_number = crl
            .crl_number()
            .ok_or_else(|| "CRL is missing the CRL Number extension".to_string())
            .and_then(|num| {
                num.try_into()
                    .map_err(|_| "CRL Number does not fit in a u32".to_string())
            });
        Ok(Self {
            der: der.to_vec(),
            next_update: crl.next_update().map(|t| t.timestamp()),
            revoked_serials,
            crl_number,
        })
    }

    fn parse(&self) -> Result<CertificateRevocationList<'_>> {
        let (_, crl) = parse_x509_crl(&self.der).context("failed to parse X.509 CRL")?;
        Ok(crl)
    }

    /// `true` if this CRL's signature was made by `issuer`'s key.
    pub(crate) fn is_issued_by(&self, issuer: &Cert) -> Result<bool> {
        let crl = self.parse()?;
        let issuer_cert = issuer.parse()?;
        Ok(crl.verify_signature(issuer_cert.public_key()).is_ok())
    }

    /// The CRL's `nextUpdate` field, as a Unix timestamp, if present.
    pub(crate) fn next_update(&self) -> Option<i64> {
        self.next_update
    }

    /// `true` if `now` is past `nextUpdate` (treated as not-expired if absent).
    pub(crate) fn is_expired(&self, now: &DateTime<Utc>) -> bool {
        self.next_update
            .is_some_and(|next_update| next_update < now.timestamp())
    }

    /// `true` if a certificate with the given raw (big-endian) serial number
    /// bytes appears in this CRL's revoked-certificate list.
    pub(crate) fn is_revoked(&self, serial: &[u8]) -> bool {
        self.revoked_serials.contains(serial)
    }

    /// The CRL Number extension value.
    pub(crate) fn crl_number(&self) -> Result<u32> {
        self.crl_number.clone().map_err(|e| anyhow!(e))
    }
}

/// Aggregates the tightest validity window (earliest/latest issue date,
/// earliest expiration date) and an "is anything expired" flag across every
/// cert/CRL/collateral item observed during verification — replaces manual
/// min/max folding and repeated `expired |= ...` bookkeeping at each call site.
pub(crate) struct Validity {
    expired: bool,
    earliest_not_before: i64,
    latest_not_before: i64,
    earliest_not_after: i64,
}

impl Validity {
    pub(crate) fn new() -> Self {
        Self {
            expired: false,
            earliest_not_before: i64::MAX,
            latest_not_before: i64::MIN,
            earliest_not_after: i64::MAX,
        }
    }

    pub(crate) fn observe_cert(&mut self, cert: &Cert, now: &DateTime<Utc>) {
        let (not_before, not_after) = cert.validity();
        self.expired |= cert.is_expired(now);
        self.earliest_not_before = self.earliest_not_before.min(not_before);
        self.latest_not_before = self.latest_not_before.max(not_before);
        self.earliest_not_after = self.earliest_not_after.min(not_after);
    }

    pub(crate) fn observe_crl(&mut self, crl: &Crl, now: &DateTime<Utc>) {
        self.expired |= crl.is_expired(now);
    }

    /// Folds in a bare deadline (e.g. a `nextUpdate` field on signed JSON
    /// collateral, which has no matching `not_before`).
    pub(crate) fn observe_deadline(&mut self, deadline: &DateTime<Utc>, now: &DateTime<Utc>) {
        self.expired |= now > deadline;
        self.earliest_not_after = self.earliest_not_after.min(deadline.timestamp());
    }

    pub(crate) fn expired(&self) -> bool {
        self.expired
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
