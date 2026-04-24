//! DCAP ECDSA quote verification, in stages, so collateral can be verified
//! once and reused for any number of quotes:
//!
//! 1. Integrity and authenticity: [`AuthenticatedQuote::new`] checks what
//!    the quote carries itself — its attestation key signature, the QE
//!    Report's signature and binding to the attestation key, and the PCK
//!    certificate chain anchored at a [`TrustAnchor`].
//! 2. Revocation: [`Revocation::verify`] checks the CRLs against the trust
//!    anchor, and [`AuthenticatedQuote::check_revocation`] checks the
//!    quote's PCK certificates against them, giving a [`TrustedQuote`].
//! 3. TCB status endorsements: [`Endorsements::verify`] checks TCB Info and
//!    QE Identity against the trust anchor, and [`Endorsements::appraise`]
//!    matches a trusted quote against them, giving an [`Appraisal`].
//!
//! Every stage is synchronous and works on caller-provided bytes; fetching
//! collateral is left to the caller (see `dcap_verify`).

use crate::intel_dcap::cert::{Cert, CertRole, Crl, Validity};
use crate::intel_dcap::collateral_service::*;
use crate::intel_dcap::pck::PlatformInfo;
use crate::intel_dcap::quote::{QeCertificationData, Quote, SgxReportBody, parse_quote};
use crate::intel_dcap::tcb_status;
use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use scroll::Pread;
use std::collections::BTreeSet;
use tracing::debug;

// From CertType=5 ("PCK Leaf Cert || Intermediate CA Cert || Root CA Cert") we get:
const PCK_LEAF: usize = 0;
const INTERMEDIATE_CA: usize = 1;
const ROOT_CA: usize = 2;

/// The public key DCAP trust is anchored at.
///
/// Every certificate chain (the quote's PCK chain and the collateral issuer
/// chains) must chain up to this key, never to a root certificate's own
/// self-declared key, which is attacker-controlled input.
#[derive(Clone, Copy)]
pub struct TrustAnchor([u8; 65]);

impl TrustAnchor {
    /// The Intel SGX Root CA's public key (`CN=Intel SGX Root CA,
    /// O=Intel Corporation`), the root of every genuine PCK certificate chain.
    pub const INTEL_SGX_ROOT_CA: Self = Self([
        0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c,
        0xda, 0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70,
        0x55, 0x25, 0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc,
        0x4e, 0xe2, 0x6a, 0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b,
        0x09, 0x04, 0xae, 0x73, 0x94,
    ]);

    /// A trust anchor from an uncompressed SEC1 P-256 public key
    /// (`0x04 || X || Y`), e.g. the root key from an authenticated policy.
    /// Never use a key taken from a quote or other unauthenticated input.
    pub fn from_public_key(key: &[u8]) -> anyhow::Result<Self> {
        match <[u8; 65]>::try_from(key) {
            Ok(point) if point[0] == 0x04 => Ok(Self(point)),
            _ => bail!("trust anchor is not an uncompressed SEC1 P-256 public key"),
        }
    }

    fn key(&self) -> &[u8; 65] {
        &self.0
    }
}

/// Determines the PCK CA type from a PCK CA cert's Common Name, returning
/// both the [`CertRole`] (for chain validation) and the [`PckCaType`] (for
/// selecting which PCK CRL to fetch).
fn pck_ca_type(ca: &Cert) -> anyhow::Result<(CertRole, PckCaType)> {
    if ca.is_common_name(CertRole::PckPlatformCa.common_name()) {
        return Ok((CertRole::PckPlatformCa, PckCaType::Platform));
    }
    if ca.is_common_name(CertRole::PckProcessorCa.common_name()) {
        return Ok((CertRole::PckProcessorCa, PckCaType::Processor));
    }
    bail!(
        "PCK CA cert has unexpected Common Name, expected \"{}\" or \"{}\", got {:?}",
        CertRole::PckPlatformCa.common_name(),
        CertRole::PckProcessorCa.common_name(),
        ca.common_name(),
    )
}

/// Validates a collateral signing chain (as returned in the `*-Issuer-Chain`
/// PCS response headers): exactly 2 certificates — the signer (with the
/// expected Common Name for `leaf_role`) and its declared root CA, itself
/// anchored at `root`.
///
/// Returns the signer cert (the certificate whose public key verifies the
/// collateral).
fn verify_issuer_chain<'a>(
    chain: &'a [Cert],
    leaf_role: CertRole,
    root: &TrustAnchor,
    context_label: &str,
) -> anyhow::Result<&'a Cert> {
    let [signer, response_root] = chain else {
        bail!(
            "{context_label} issuer chain must contain exactly 2 certificates (signer, root CA), got {}",
            chain.len()
        );
    };
    signer
        .validate(leaf_role, response_root.public_key()?)
        .with_context(|| format!("{context_label} issuer chain signer"))?;
    response_root
        .validate(CertRole::RootCa, root.key())
        .with_context(|| format!("{context_label} issuer chain root"))?;
    Ok(signer)
}

/// Computes the matched TDX Module Identity's TCB level. Returns `None` for
/// SGX quotes (which have no SEAM module, no TEE TCB SVN array, and no
/// `tdxModule` baseline in TCB Info at all) or a TDX Module version of 0 (not
/// tracked separately from the platform TCB — matches upstream
/// `checkTdxModuleTcbStatus`, which returns `STATUS_OK` in this case).
///
/// For TDX quotes, also verifies the quote's SEAM module measurement and
/// attributes match what TCB Info declares for the selected module — this
/// binding check always runs, independent of whether a module-specific TCB
/// level is found; it verifies the TD actually ran the SEAM module TCB Info
/// claims, not just its TCB status.
fn tdx_module_tcb_level<'a>(
    is_sgx: bool,
    parsed_quote: &Quote,
    tcb_info: &'a TcbInfo<'a>,
) -> anyhow::Result<Option<&'a TcbLevel<'a>>> {
    if is_sgx {
        return Ok(None);
    }

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
    let tdx_module_version = parsed_quote.tcb_svn()[1];
    let tdx_module_isvsvn = parsed_quote.tcb_svn()[0];

    let tdx_module_identity = tcb_status::find_tdx_module_identity(tcb_info, tdx_module_version)?;
    let (tdx_module_mrsigner, tdx_module_attributes) =
        tcb_status::expected_seam_identity(tcb_info, tdx_module_identity)?;

    let quote_mrsigner_seam = parsed_quote
        .mrsigner_seam()
        .context("quote is missing mrsignerSeam")?;
    if tdx_module_mrsigner != quote_mrsigner_seam.as_slice() {
        bail!("Quote MRSIGNERSEAM does not match TCB Info TDX Module mrsigner");
    }

    let quote_seam_attributes = parsed_quote
        .seam_attributes()
        .context("quote is missing seamAttributes")?;
    if quote_seam_attributes != &[0u8; 8] || quote_seam_attributes != &**tdx_module_attributes {
        bail!(
            "Quote SEAMATTRIBUTES does not match TCB Info TDX Module attributes, or is not zeroed"
        );
    }

    tdx_module_identity
        .map(|identity| {
            tcb_status::find_tcb_level_by_isvsvn(&identity.tcb_levels, tdx_module_isvsvn as u16)
                .context("no matching TDX Module Identity TCB level found for quote's TEE TCB SVN")
        })
        .transpose()
}

/// Loads the quote's own embedded 3-cert PCK chain (leaf, intermediate CA,
/// root CA).
fn load_pck_chain(qe_cert_data: &QeCertificationData) -> anyhow::Result<Vec<Cert>> {
    Cert::chain_from_pem(qe_cert_data.certificates, 3).context(
        "PCK certificate chain must contain exactly 3 certificates (leaf, intermediate CA, root CA)",
    )
}

/// Validates the quote's PCK chain up to `root`. Returns the PCK CA role
/// (Platform vs Processor), determined from the intermediate's Common Name.
fn validate_pck_chain(pck_certificates: &[Cert], root: &TrustAnchor) -> anyhow::Result<CertRole> {
    let (ca_role, _) = pck_ca_type(&pck_certificates[INTERMEDIATE_CA])?;

    // Sanity-check that the quote's own embedded root cert is internally
    // well-formed (self-signed, with the expected Common Name). This says
    // nothing about trust on its own — see the anchoring below.
    pck_certificates[ROOT_CA]
        .validate(CertRole::RootCa, pck_certificates[ROOT_CA].public_key()?)
        .context("PCK root CA certificate is not self-signed with the expected identity")?;

    // Certificate/CRL expiration is tracked separately (matching upstream
    // DCAP QVL/QvE semantics, where expired-but-otherwise-valid collateral is
    // non-fatal and surfaced via the `collateral_expiration_status` claim), so
    // chain verification itself does not enforce validity periods.
    //
    // Trust is anchored at `root`, never at `pck_certificates[ROOT_CA]`'s own
    // self-declared key: that cert is attacker-controlled input embedded in
    // the quote, so it can only be used for the self-signature sanity check
    // above, not as a verification key.
    pck_certificates[INTERMEDIATE_CA].validate(ca_role, root.key())?;
    pck_certificates[PCK_LEAF].validate(
        CertRole::PckLeaf,
        pck_certificates[INTERMEDIATE_CA].public_key()?,
    )?;

    Ok(ca_role)
}

/// Why a quote failed authentication: the checks on what the quote carries
/// itself (QVL quote format, signature, QE Report and PCK certificate checks).
#[derive(Debug, thiserror::Error)]
pub enum AuthenticationError {
    #[error("malformed or unsupported quote: {0:#}")]
    Quote(anyhow::Error),
    #[error("quote signature verification failed")]
    QuoteSignature,
    #[error("QE Report ReportData does not bind the attestation key")]
    QeReportBinding,
    #[error("QE Report signature verification failed")]
    QeReportSignature,
    #[error("invalid PCK certificate chain: {0:#}")]
    PckChain(anyhow::Error),
}

/// Stage 1: a quote whose integrity and authenticity have been verified
/// against a [`TrustAnchor`] — its attestation key signature, the QE Report's
/// signature and binding to the attestation key, and the PCK certificate
/// chain. Not yet checked for revocation: see
/// [`AuthenticatedQuote::check_revocation`].
pub struct AuthenticatedQuote<'q> {
    quote: Quote<'q>,
    is_sgx: bool,
    qe_report_body: SgxReportBody,
    pck_certificates: Vec<Cert>,
    pck_ca: CertRole,
    platform_info: PlatformInfo,
    root_key_id: [u8; 48],
}

impl<'q> AuthenticatedQuote<'q> {
    /// Parses `quote` and verifies its integrity and authenticity up to `root`.
    pub fn new(quote: &'q [u8], root: &TrustAnchor) -> Result<Self, AuthenticationError> {
        let parsed_quote = parse_quote(quote).map_err(AuthenticationError::Quote)?;
        // `parse_quote` only ever pairs version 3 with SGX and versions 4/5 with
        // TDX (see its own dispatch), so the quote variant already determines this.
        let is_sgx = matches!(parsed_quote, Quote::V3 { .. });

        if !parsed_quote
            .verify_ak_signature(quote)
            .map_err(AuthenticationError::Quote)?
        {
            return Err(AuthenticationError::QuoteSignature);
        }

        let qe_cert_data = &parsed_quote.cert_data().qe_certification_data;

        // Test that the AK pubkey and QE authentication data are bound to
        // Quoting Enclave's Report Data:
        // sha256(Attestation Key || QE Authentication Data) || 32-0x00’s
        let qe_report_body = (qe_cert_data.qe_report.report)
            .pread::<SgxReportBody>(0)
            .map_err(|e| {
                AuthenticationError::Quote(anyhow!("failed to parse QE report body: {e}"))
            })?;
        if !parsed_quote.verify_qe_report_data_binding(&qe_report_body.report_data) {
            return Err(AuthenticationError::QeReportBinding);
        }

        let pck_certificates =
            load_pck_chain(qe_cert_data).map_err(AuthenticationError::PckChain)?;
        if !pck_certificates[PCK_LEAF]
            .verify_message(
                &qe_cert_data.qe_report.report,
                &qe_cert_data.qe_report.sig_r,
                &qe_cert_data.qe_report.sig_s,
            )
            .map_err(AuthenticationError::PckChain)?
        {
            return Err(AuthenticationError::QeReportSignature);
        }
        let pck_ca =
            validate_pck_chain(&pck_certificates, root).map_err(AuthenticationError::PckChain)?;
        let platform_info = pck_certificates[PCK_LEAF]
            .platform_info(pck_ca == CertRole::PckPlatformCa)
            .map_err(AuthenticationError::PckChain)?;
        let root_key_id = pck_certificates[ROOT_CA]
            .key_id()
            .map_err(AuthenticationError::PckChain)?;

        Ok(Self {
            quote: parsed_quote,
            is_sgx,
            qe_report_body,
            pck_certificates,
            pck_ca,
            platform_info,
            root_key_id,
        })
    }

    /// The TEE that produced the quote.
    pub fn tee(&self) -> IntelTee {
        if self.is_sgx {
            IntelTee::Sgx
        } else {
            IntelTee::Tdx
        }
    }

    /// The PCK CA that issued the quote's PCK certificate, which selects the
    /// PCK CRL to check it against.
    pub fn pck_ca_type(&self) -> PckCaType {
        match self.pck_ca {
            CertRole::PckPlatformCa => PckCaType::Platform,
            _ => PckCaType::Processor,
        }
    }

    /// Where the (verified) PCK CA certificate says the Root CA CRL is.
    pub fn root_ca_crl_distribution_point(&self) -> Option<&str> {
        self.pck_certificates[INTERMEDIATE_CA].crl_distribution_point()
    }

    /// Stage 2: checks the quote's PCK certificates against verified CRLs.
    pub fn check_revocation(
        self,
        revocation: &Revocation<'_>,
    ) -> Result<TrustedQuote<'q>, RevocationError> {
        check_pck_crl_issuer(revocation.pck_crl_ca, self.pck_ca)?;
        check_not_revoked(
            &revocation.root_ca_crl,
            &self.pck_certificates[INTERMEDIATE_CA],
            "PCK intermediate CA certificate",
        )?;
        check_not_revoked(
            &revocation.pck_crl,
            &self.pck_certificates[PCK_LEAF],
            "PCK certificate",
        )?;

        let mut validity = revocation.validity;
        for cert in &self.pck_certificates {
            validity.observe_cert(cert);
        }
        Ok(TrustedQuote {
            quote: self,
            pck_crl_num: revocation.pck_crl_num,
            root_ca_crl_num: revocation.root_ca_crl_num,
            validity,
        })
    }
}

/// Why CRLs, or a quote checked against them, were rejected.
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("invalid Root CA CRL: {0:#}")]
    RootCaCrl(anyhow::Error),
    #[error("invalid PCK CRL: {0:#}")]
    PckCrl(anyhow::Error),
    #[error("PCK CRL was issued by the {crl}, but the quote's PCK certificate by the {quote}")]
    PckCaMismatch {
        crl: &'static str,
        quote: &'static str,
    },
    #[error("{0} is revoked")]
    Revoked(&'static str),
}

/// The CRLs for verifying quotes from one platform, borrowed from the caller.
pub struct RevocationData<'p> {
    /// DER.
    pub root_ca_crl: &'p [u8],
    /// DER.
    pub pck_crl: &'p [u8],
    /// PEM: PCK CA (Platform or Processor) cert || Root CA cert.
    pub pck_crl_issuer_chain: &'p [u8],
}

/// [`RevocationData`] whose CRLs have been verified against a
/// [`TrustAnchor`], ready to check any number of quotes.
pub struct Revocation<'p> {
    root_ca_crl: Crl<'p>,
    root_ca_crl_num: u32,
    pck_crl: Crl<'p>,
    pck_crl_num: u32,
    /// The PCK CA that issued the PCK CRL.
    pck_crl_ca: CertRole,
    validity: Validity,
}

impl<'p> Revocation<'p> {
    /// Verifies both CRLs (and the PCK CRL's issuer chain) against `root`.
    pub fn verify(data: &RevocationData<'p>, root: &TrustAnchor) -> Result<Self, RevocationError> {
        let mut validity = Validity::new();
        let root_ca_crl = verify_root_ca_crl(data.root_ca_crl, root, &mut validity)
            .map_err(RevocationError::RootCaCrl)?;
        let root_ca_crl_num = root_ca_crl
            .crl_number()
            .map_err(RevocationError::RootCaCrl)?;
        let (pck_crl, pck_crl_ca) =
            verify_pck_crl(data.pck_crl, data.pck_crl_issuer_chain, root, &mut validity)
                .map_err(RevocationError::PckCrl)?;
        let pck_crl_num = pck_crl.crl_number().map_err(RevocationError::PckCrl)?;
        Ok(Self {
            root_ca_crl,
            root_ca_crl_num,
            pck_crl,
            pck_crl_num,
            pck_crl_ca,
            validity,
        })
    }
}

/// A quote that has been authenticated and checked for revocation, ready to
/// be appraised against [`Endorsements`].
pub struct TrustedQuote<'q> {
    quote: AuthenticatedQuote<'q>,
    pck_crl_num: u32,
    root_ca_crl_num: u32,
    /// Collected over the PCK certificates and the CRLs.
    validity: Validity,
}

impl TrustedQuote<'_> {
    /// The TEE that produced the quote.
    pub fn tee(&self) -> IntelTee {
        self.quote.tee()
    }

    /// The platform information from the PCK leaf certificate.
    pub fn platform_info(&self) -> &PlatformInfo {
        &self.quote.platform_info
    }

    /// SHA-384 of the quote's PCK root CA public key.
    pub fn root_key_id(&self) -> &[u8; 48] {
        &self.quote.root_key_id
    }

    pub fn pck_crl_num(&self) -> u32 {
        self.pck_crl_num
    }

    pub fn root_ca_crl_num(&self) -> u32 {
        self.root_ca_crl_num
    }
}

/// Why endorsements were rejected.
#[derive(Debug, thiserror::Error)]
pub enum EndorsementError {
    #[error("invalid TCB Info: {0:#}")]
    TcbInfo(anyhow::Error),
    #[error("invalid QE Identity: {0:#}")]
    QeIdentity(anyhow::Error),
}

/// The TCB status endorsements for one platform, borrowed from the caller.
pub struct EndorsementData<'p> {
    /// The signed TCB Info JSON, exactly as Intel issued it.
    pub tcb_info: &'p [u8],
    /// PEM: TCB Signing cert || Root CA cert.
    pub tcb_info_issuer_chain: &'p [u8],
    /// The signed QE Identity JSON, exactly as Intel issued it.
    pub qe_identity: &'p [u8],
    /// PEM: TCB Signing cert || Root CA cert.
    pub qe_identity_issuer_chain: &'p [u8],
}

/// Stage 3: [`EndorsementData`] whose issuer chains and signatures have been
/// verified against a [`TrustAnchor`], parsed once and borrowing from the
/// caller's bytes, ready to appraise any number of quotes from the platform
/// it describes.
pub struct Endorsements<'p> {
    /// SGX or TDX, from TCB Info's `id`.
    is_sgx: bool,
    tcb_info: TcbInfo<'p>,
    qe_identity: EnclaveIdentity<'p>,
    /// Collected over the endorsements' certificates and deadlines.
    validity: Validity,
}

/// Why a quote's appraisal against endorsements failed.
#[derive(Debug, thiserror::Error)]
pub enum AppraisalError {
    #[error("endorsements were generated for {endorsements}, but the quote is from {quote}")]
    TeeMismatch {
        endorsements: &'static str,
        quote: &'static str,
    },
    #[error("QE Report does not match QE Identity: {0:#}")]
    QeIdentityMismatch(anyhow::Error),
    #[error("{0}")]
    PlatformMismatch(&'static str),
    #[error("TCB evaluation failed: {0:#}")]
    Tcb(anyhow::Error),
}

impl<'p> Endorsements<'p> {
    /// Verifies TCB Info and QE Identity against `root`.
    pub fn verify(
        data: &EndorsementData<'p>,
        root: &TrustAnchor,
    ) -> Result<Self, EndorsementError> {
        let mut validity = Validity::new();
        let (tcb_info, is_sgx) = verify_tcb_info(
            data.tcb_info,
            data.tcb_info_issuer_chain,
            root,
            &mut validity,
        )
        .map_err(EndorsementError::TcbInfo)?;
        let qe_identity = verify_qe_identity(
            data.qe_identity,
            data.qe_identity_issuer_chain,
            root,
            is_sgx,
            &mut validity,
        )
        .map_err(EndorsementError::QeIdentity)?;
        Ok(Self {
            is_sgx,
            tcb_info,
            qe_identity,
            validity,
        })
    }

    /// Appraises a trusted quote from the platform these endorsements
    /// describe: QE Report against QE Identity, and the quote's TCB against
    /// TCB Info.
    pub fn appraise(&self, quote: &TrustedQuote<'_>) -> Result<Appraisal<'_>, AppraisalError> {
        let authenticated = &quote.quote;
        check_tee(self.is_sgx, authenticated.is_sgx)?;
        check_qe_report(&self.qe_identity, &authenticated.qe_report_body)
            .map_err(AppraisalError::QeIdentityMismatch)?;

        let qe_tcb_level = tcb_status::find_tcb_level_by_isvsvn(
            &self.qe_identity.tcb_levels,
            u16::from_le_bytes(authenticated.qe_report_body.isv_svn),
        )
        .context("no matching QE Identity TCB level found for QE Report isvsvn")
        .map_err(AppraisalError::Tcb)?;

        debug!("QE TCB level: {:?}", qe_tcb_level.tcb_status);

        let platform_info = &authenticated.platform_info;
        if *self.tcb_info.fmspc != platform_info.fmspc {
            return Err(AppraisalError::PlatformMismatch(
                "TCB Info FMSPC does not match PCK certificate FMSPC",
            ));
        }
        if *self.tcb_info.pce_id != platform_info.pceid {
            return Err(AppraisalError::PlatformMismatch(
                "TCB Info PCEID does not match PCK certificate PCEID",
            ));
        }

        // Go over the sorted collection of TCB Levels retrieved from
        // TCB Info starting from the first item on the list:
        // Step 3.c (TD Report TEE TCB SVNs) is TDX-only; `tcb_svn()` means
        // something else entirely for SGX (it's `cpu_svn`, already covered by
        // `platform_info.tcb_components`/`pcesvn` above), so it doesn't apply.
        let td_svns: Option<&[u8]> = if authenticated.is_sgx {
            None
        } else {
            Some(authenticated.quote.tcb_svn())
        };
        let tcb_level = tcb_status::find_matching_tcb_level(
            &self.tcb_info.tcb_levels,
            &platform_info.tcb_components,
            platform_info.pcesvn,
            td_svns,
        )
        .map_err(AppraisalError::Tcb)?;

        let tdx_module_level =
            tdx_module_tcb_level(authenticated.is_sgx, &authenticated.quote, &self.tcb_info)
                .map_err(AppraisalError::Tcb)?;

        let tcb_status = tcb_status::converge(
            tcb_level.tcb_status,
            tdx_module_level.map(|l| l.tcb_status),
            qe_tcb_level.tcb_status,
            authenticated.quote.tee_tcb_svn2(),
            &self.tcb_info,
        )
        .map_err(AppraisalError::Tcb)?;

        debug!("converged tcb_status: {tcb_status}");

        let mut validity = quote.validity;
        validity.merge(&self.validity);

        Ok(Appraisal {
            tcb_status,
            advisory_ids: tcb_status::merge_advisory_ids(tcb_level, qe_tcb_level, tdx_module_level),
            tcb_date: tcb_level.tcb_date.min(qe_tcb_level.tcb_date),
            tcb_eval_num: self
                .tcb_info
                .tcb_evaluation_data_number
                .min(self.qe_identity.tcb_evaluation_data_number),
            validity,
        })
    }
}

/// The outcome of appraising a trusted quote against endorsements.
pub struct Appraisal<'e> {
    pub tcb_status: TcbStatus,
    /// Advisory IDs from the matched TCB Info, QE Identity and TDX Module
    /// TCB levels, deduplicated and sorted.
    pub advisory_ids: BTreeSet<&'e str>,
    /// The earlier of the matched platform and QE TCB levels' dates.
    pub tcb_date: DateTime<Utc>,
    pub tcb_eval_num: u32,
    /// Collected over everything verified: the quote's PCK certificates, the
    /// CRLs and the endorsements.
    pub validity: Validity,
}

impl Appraisal<'_> {
    /// Whether any certificate, CRL or endorsement had expired by `now`.
    /// Reported, not fatal, as in the DCAP QVL/QvE.
    pub fn expired(&self, now: &DateTime<Utc>) -> bool {
        self.validity.expired(now)
    }
}

/// Requires endorsements generated for the quote's TEE (QVL 4.1.2.5.10).
/// TDX TCB levels also carry SGX components, so without this an SGX quote
/// could be matched against TDX TCB Info for the same FMSPC.
fn check_tee(endorsements_are_sgx: bool, quote_is_sgx: bool) -> Result<(), AppraisalError> {
    let tee = |is_sgx| if is_sgx { "SGX" } else { "TDX" };
    if endorsements_are_sgx != quote_is_sgx {
        return Err(AppraisalError::TeeMismatch {
            endorsements: tee(endorsements_are_sgx),
            quote: tee(quote_is_sgx),
        });
    }
    Ok(())
}

/// Requires the PCK CRL to come from the PCK CA that issued the quote's PCK
/// certificate (Platform vs Processor).
fn check_pck_crl_issuer(crl_ca: CertRole, quote_ca: CertRole) -> Result<(), RevocationError> {
    if crl_ca != quote_ca {
        return Err(RevocationError::PckCaMismatch {
            crl: crl_ca.common_name(),
            quote: quote_ca.common_name(),
        });
    }
    Ok(())
}

fn check_not_revoked(
    crl: &Crl<'_>,
    cert: &Cert,
    what: &'static str,
) -> Result<(), RevocationError> {
    if crl.is_revoked(cert.serial_number()) {
        return Err(RevocationError::Revoked(what));
    }
    Ok(())
}

/// Verifies the TCB Info's issuer chain up to `root` and its signature, and
/// that it's a v3+ TCB Info for SGX or TDX. Returns the parsed TCB Info,
/// borrowing from `tcb_info`, and whether it's for SGX.
fn verify_tcb_info<'p>(
    tcb_info: &'p [u8],
    issuer_chain: &[u8],
    root: &TrustAnchor,
    validity: &mut Validity,
) -> anyhow::Result<(TcbInfo<'p>, bool)> {
    let tcb_cert_chain = Cert::chain_from_pem(issuer_chain, 2)?;
    let tcb_info_signer =
        verify_issuer_chain(&tcb_cert_chain, CertRole::TcbSigning, root, "TCB Info")?;
    validity.observe_cert(tcb_info_signer);
    validity.observe_cert(&tcb_cert_chain[1]);

    let tcb_info_json: TcbInfoJson =
        serde_json::from_slice(tcb_info).context("failed to deserialize TCB Info collateral")?;

    // Intel signs the `tcbInfo` object's exact bytes, so verify over those
    // as they appear in the collateral, before parsing them.
    if !tcb_info_signer.verify_message(
        tcb_info_json.tcb_info.get().as_bytes(),
        &tcb_info_json.signature[..32],
        &tcb_info_json.signature[32..],
    )? {
        bail!("TCB Info ECDSA signature verification failed.");
    }

    let tcb_info = tcb_info_json
        .tcb_info()
        .context("failed to deserialize TCB Info tcbInfo")?;

    // Version 2 (SGX only, deprecated) has no `id` and already fails to parse
    // above; TDX needs version 3 (QVL 4.1.2.5.10).
    let is_sgx = match tcb_info.id {
        "SGX" => true,
        "TDX" => false,
        other => bail!("TCB Info has unexpected id \"{other}\", expected \"SGX\" or \"TDX\""),
    };
    if tcb_info.version < 3 {
        bail!(
            "TCB Info version {} is not supported, expected 3 or later",
            tcb_info.version
        );
    }

    validity.observe_deadline(&tcb_info.next_update);

    Ok((tcb_info, is_sgx))
}

/// Verifies the QE Identity's issuer chain up to `root` and its signature,
/// and that it's for the TEE `is_sgx` selects. Returns the parsed QE
/// Identity, borrowing from `qe_identity`.
fn verify_qe_identity<'p>(
    qe_identity: &'p [u8],
    issuer_chain: &[u8],
    root: &TrustAnchor,
    is_sgx: bool,
    validity: &mut Validity,
) -> anyhow::Result<EnclaveIdentity<'p>> {
    let qe_identity_cert_chain = Cert::chain_from_pem(issuer_chain, 2)?;
    let qe_identity_signer = verify_issuer_chain(
        &qe_identity_cert_chain,
        CertRole::TcbSigning,
        root,
        "QE Identity",
    )?;
    validity.observe_cert(qe_identity_signer);
    validity.observe_cert(&qe_identity_cert_chain[1]);

    let qe_identity: QeIdentity = serde_json::from_slice(qe_identity)
        .context("failed to deserialize QE Identity collateral")?;

    // Intel signs the `enclaveIdentity` object's exact bytes, so verify
    // over those as they appear in the collateral, before parsing them.
    if !qe_identity_signer.verify_message(
        qe_identity.enclave_identity.get().as_bytes(),
        &qe_identity.signature[..32],
        &qe_identity.signature[32..],
    )? {
        bail!("QE Identity ECDSA signature verification failed.");
    }

    let enclave_identity = qe_identity
        .enclave_identity()
        .context("failed to deserialize QE Identity enclaveIdentity")?;

    // QE Identity v1 predates TDX (QVL 4.1.2.5.15).
    if !is_sgx && enclave_identity.version < 2 {
        bail!(
            "QE Identity version {} is invalid for TDX",
            enclave_identity.version
        );
    }
    let expected_qe_id = if is_sgx { "QE" } else { "TD_QE" };
    if enclave_identity.id != expected_qe_id {
        bail!(
            "unexpected QE Identity id, expected \"{expected_qe_id}\", got \"{}\"",
            enclave_identity.id
        );
    }

    validity.observe_deadline(&enclave_identity.next_update);

    Ok(enclave_identity)
}

/// Checks the quote's QE Report against the QE Identity (miscselect,
/// attributes, mrsigner, isvprodid).
fn check_qe_report(
    qe_identity: &EnclaveIdentity<'_>,
    qe_report_body: &SgxReportBody,
) -> anyhow::Result<()> {
    let flags_mask: [u8; 8] = qe_identity.attributes_mask[..8].try_into()?;
    let flags: [u8; 8] = qe_identity.attributes[..8].try_into()?;

    let xfrm_mask: [u8; 8] = qe_identity.attributes_mask[8..].try_into()?;
    let xfrm: [u8; 8] = qe_identity.attributes[8..].try_into()?;

    if (u32::from_le_bytes(qe_report_body.misc_select)
        & u32::from_le_bytes(*qe_identity.miscselect_mask))
        != u32::from_le_bytes(*qe_identity.miscselect)
    {
        bail!("QE Report miscselect does not match QE Identity");
    }
    if (u64::from_le_bytes(qe_report_body.attributes_flags) & u64::from_le_bytes(flags_mask))
        != u64::from_le_bytes(flags)
    {
        bail!("QE Report attributes flags do not match QE Identity");
    }
    if (u64::from_le_bytes(qe_report_body.attributes_xfrm) & u64::from_le_bytes(xfrm_mask))
        != u64::from_le_bytes(xfrm)
    {
        bail!("QE Report attributes xfrm do not match QE Identity");
    }
    if *qe_identity.mrsigner != qe_report_body.mr_signer {
        bail!("QE Report mrsigner does not match QE Identity");
    }
    if qe_identity.isvprodid != u16::from_le_bytes(qe_report_body.isv_prod_id) {
        bail!("QE Report isvprodid does not match QE Identity");
    }
    Ok(())
}

/// Verifies the Root CA CRL was issued by `root` (never the quote's own
/// embedded root cert — see [`load_and_validate_pck_chain`]).
fn verify_root_ca_crl<'p>(
    der: &'p [u8],
    root: &TrustAnchor,
    validity: &mut Validity,
) -> anyhow::Result<Crl<'p>> {
    let crl = Crl::from_der(der)?;
    if !crl.is_issued_by(root.key()) {
        bail!("Root CA CRL signature verification failed");
    }
    validity.observe_crl(&crl);
    Ok(crl)
}

/// Verifies the PCK CRL's issuer chain up to `root` and its signature.
/// Returns the CRL and the PCK CA (Platform or Processor) that issued it.
fn verify_pck_crl<'p>(
    der: &'p [u8],
    issuer_chain: &[u8],
    root: &TrustAnchor,
    validity: &mut Validity,
) -> anyhow::Result<(Crl<'p>, CertRole)> {
    let crl = Crl::from_der(der)?;
    let chain = Cert::chain_from_pem(issuer_chain, 2)?;
    let (ca_role, _) = pck_ca_type(&chain[0]).context("PCK CRL issuer chain signer")?;
    let signer = verify_issuer_chain(&chain, ca_role, root, "PCK CRL")?;
    if !crl.is_issued_by(signer.public_key()?) {
        bail!("PCK CRL signature verification failed");
    }
    validity.observe_crl(&crl);
    Ok((crl, ca_role))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// Minimal DCAP-shaped PKI, built with `openssl`, for exercising
    /// collateral and CRL checks against certs/CRLs whose content
    /// (revoked serials, signing key) is under the test's control — something
    /// impractical to arrange against the real Intel PCS. `openssl` here is a
    /// test-fixture generator only, same as `crypto.rs`'s own test helpers;
    /// production code never touches it.
    mod pki {
        use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::bn::BigNum;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::{PKey, Private};
        use openssl::x509::extension::{BasicConstraints, CrlNumber};
        use openssl::x509::{
            X509, X509CrlBuilder, X509Extension, X509NameBuilder, X509RevokedBuilder,
        };

        pub struct TestCert {
            pub key: EcKey<Private>,
            pub x509: X509,
        }

        impl TestCert {
            /// PEM encoding, for `Cert::chain_from_pem`.
            pub fn pem(&self) -> Vec<u8> {
                self.x509.to_pem().expect("PEM-encode test cert")
            }

            /// Raw (big-endian) DER serial number bytes, matching what a
            /// [`super::super::Cert`] built from this cert's PEM would report
            /// via `serial_number()`.
            pub fn serial(&self) -> Vec<u8> {
                self.x509
                    .serial_number()
                    .to_bn()
                    .expect("serial as BigNum")
                    .to_vec()
            }
        }

        /// Builds a self-signed (if `issuer` is `None`) or `issuer`-signed
        /// ECDSA-P256-SHA256 X.509 v3 certificate with the given subject CN.
        pub fn cert(cn: &str, issuer: Option<&TestCert>, is_ca: bool) -> TestCert {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256 group");
            let key = EcKey::generate(&group).expect("generate EC key");
            let pkey = PKey::from_ec_key(key.clone()).expect("wrap EC key");

            let mut name = X509NameBuilder::new().expect("X509NameBuilder");
            name.append_entry_by_text("CN", cn).expect("append CN");
            let name = name.build();

            let mut builder = X509::builder().expect("X509::builder");
            builder.set_version(2).expect("set X.509 v3");
            builder.set_subject_name(&name).expect("set subject");
            builder
                .set_issuer_name(issuer.map_or(&name, |i| i.x509.subject_name()))
                .expect("set issuer");
            builder.set_pubkey(&pkey).expect("set pubkey");
            builder
                .set_not_before(&Asn1Time::days_from_now(0).expect("not_before"))
                .expect("set not_before");
            builder
                .set_not_after(&Asn1Time::days_from_now(3650).expect("not_after"))
                .expect("set not_after");

            let serial = BigNum::from_u32(rand_serial()).expect("serial BigNum");
            builder
                .set_serial_number(&Asn1Integer::from_bn(&serial).expect("serial Asn1Integer"))
                .expect("set serial");

            if is_ca {
                let bc = BasicConstraints::new()
                    .ca()
                    .build()
                    .expect("BasicConstraints");
                builder
                    .append_extension(bc)
                    .expect("append BasicConstraints");
            }

            let signing_key = issuer.map_or(&key, |i| &i.key);
            let signing_pkey = PKey::from_ec_key(signing_key.clone()).expect("wrap signing key");
            builder
                .sign(&signing_pkey, MessageDigest::sha256())
                .expect("sign cert");

            TestCert {
                key,
                x509: builder.build(),
            }
        }

        /// Builds a DER-encoded CRL signed by `issuer`, revoking `revoked_serials`.
        pub fn crl(issuer: &TestCert, revoked_serials: &[&[u8]]) -> Vec<u8> {
            let mut builder = X509CrlBuilder::new().expect("X509CrlBuilder");
            builder
                .set_issuer_name(issuer.x509.subject_name())
                .expect("set CRL issuer");
            let now = Asn1Time::days_from_now(0).expect("now");
            builder.set_last_update(&now).expect("set lastUpdate");
            builder
                .set_next_update(&Asn1Time::days_from_now(30).expect("nextUpdate"))
                .expect("set nextUpdate");

            // AuthorityKeyIdentifier/CrlNumber aren't DCAP requirements as
            // such (`Crl::from_der` doesn't need them) — `X509CrlBuilder`
            // just refuses to build a CRL without them. The keyIdentifier
            // value itself is never checked by anything under test, so a
            // fixed, arbitrary octet string avoids needing the issuer cert
            // to carry a matching SubjectKeyIdentifier extension.
            let aki = X509Extension::new_from_der(
                &Asn1Object::from_str("2.5.29.35").expect("AKI OID"),
                false,
                &Asn1OctetString::new_from_bytes(b"\x30\x03\x80\x01\x00").expect("AKI DER"),
            )
            .expect("AuthorityKeyIdentifier extension");
            builder.append_extension(aki).expect("append AKI");
            builder
                .append_extension(
                    CrlNumber::new(BigNum::from_u32(1).expect("crl number BigNum"))
                        .expect("CrlNumber")
                        .build()
                        .expect("build CrlNumber ext"),
                )
                .expect("append CrlNumber");

            for serial in revoked_serials {
                let mut revoked = X509RevokedBuilder::new().expect("X509RevokedBuilder");
                let bn = BigNum::from_slice(serial).expect("serial BigNum");
                revoked
                    .set_serial_number(&Asn1Integer::from_bn(&bn).expect("Asn1Integer"))
                    .expect("set revoked serial");
                revoked
                    .set_revocation_date(&now)
                    .expect("set revocationDate");
                builder.add_revoked(revoked.build()).expect("add_revoked");
            }

            let signing_pkey = PKey::from_ec_key(issuer.key.clone()).expect("wrap issuer key");
            builder
                .sign(&signing_pkey, MessageDigest::sha256())
                .expect("sign CRL");

            builder
                .build()
                .expect("build CRL")
                .to_der()
                .expect("DER-encode CRL")
        }

        /// Signs `data` the way Intel signs TCB Info and QE Identity:
        /// ECDSA-P256-SHA256, returned as hex-encoded `r || s`.
        pub fn sign(signer: &TestCert, data: &[u8]) -> String {
            let sig = openssl::ecdsa::EcdsaSig::sign(&openssl::sha::sha256(data), &signer.key)
                .expect("ECDSA sign");
            let mut rs = sig.r().to_vec_padded(32).expect("r");
            rs.extend(sig.s().to_vec_padded(32).expect("s"));
            hex::encode(rs)
        }

        /// A serial number distinguishable from the other test certs'.
        fn rand_serial() -> u32 {
            use std::sync::atomic::{AtomicU32, Ordering};
            static NEXT: AtomicU32 = AtomicU32::new(1);
            NEXT.fetch_add(1, Ordering::Relaxed)
        }
    }

    fn cert_of(test_cert: &pki::TestCert) -> Cert {
        Cert::chain_from_pem(&test_cert.pem(), 1).unwrap().remove(0)
    }

    fn anchor_of(root: &pki::TestCert) -> TrustAnchor {
        TrustAnchor::from_public_key(cert_of(root).public_key().unwrap()).unwrap()
    }

    fn chain_pem(signer: &pki::TestCert, root: &pki::TestCert) -> Vec<u8> {
        let mut chain = signer.pem();
        chain.extend_from_slice(&root.pem());
        chain
    }

    /// A signed TCB Info document with no TCB levels.
    fn signed_tcb_info(signer: &pki::TestCert, id: &str, version: u8) -> Vec<u8> {
        let tcb_info = format!(
            r#"{{"id":"{id}","version":{version},"issueDate":"2024-01-01T00:00:00Z","nextUpdate":"2099-01-01T00:00:00Z","fmspc":"000000000000","pceId":"0000","tcbType":0,"tcbEvaluationDataNumber":1,"tcbLevels":[]}}"#
        );
        let signature = pki::sign(signer, tcb_info.as_bytes());
        format!(r#"{{"tcbInfo":{tcb_info},"signature":"{signature}"}}"#).into_bytes()
    }

    /// A signed QE Identity document matching an all-zero QE Report body.
    fn signed_qe_identity(signer: &pki::TestCert, id: &str, version: u8) -> Vec<u8> {
        let enclave_identity = format!(
            r#"{{"id":"{id}","version":{version},"issueDate":"2024-01-01T00:00:00Z","nextUpdate":"2099-01-01T00:00:00Z","tcbEvaluationDataNumber":1,"miscselect":"00000000","miscselectMask":"FFFFFFFF","attributes":"{zero16}","attributesMask":"{zero16}","mrsigner":"{zero32}","isvprodid":0,"tcbLevels":[]}}"#,
            zero16 = "00".repeat(16),
            zero32 = "00".repeat(32),
        );
        let signature = pki::sign(signer, enclave_identity.as_bytes());
        format!(r#"{{"enclaveIdentity":{enclave_identity},"signature":"{signature}"}}"#)
            .into_bytes()
    }

    #[test]
    fn intel_trust_anchor_matches_genuine_root_ca() {
        // The Intel SGX Root CA certificate embedded in a genuine quote's PCK
        // chain carries the trust anchor's key.
        let quote = std::fs::read("./test_data/tdx_quote_4.dat").unwrap();
        let parsed = parse_quote(&quote).unwrap();
        let chain = load_pck_chain(&parsed.cert_data().qe_certification_data).unwrap();
        assert!(chain[ROOT_CA].is_common_name(CertRole::RootCa.common_name()));
        assert_eq!(
            chain[ROOT_CA].public_key().unwrap(),
            TrustAnchor::INTEL_SGX_ROOT_CA.key()
        );
    }

    #[test]
    fn trust_anchor_requires_uncompressed_p256_key() {
        assert!(TrustAnchor::from_public_key(TrustAnchor::INTEL_SGX_ROOT_CA.key()).is_ok());
        assert!(TrustAnchor::from_public_key(&[0x04; 64]).is_err());
        let mut compressed = *TrustAnchor::INTEL_SGX_ROOT_CA.key();
        compressed[0] = 0x02;
        assert!(TrustAnchor::from_public_key(&compressed).is_err());
    }

    #[test]
    fn authenticated_quote_is_anchored_at_trust_anchor() {
        let quote = std::fs::read("./test_data/tdx_quote_4.dat").unwrap();

        let authenticated = AuthenticatedQuote::new(&quote, &TrustAnchor::INTEL_SGX_ROOT_CA)
            .expect("genuine quote chains up to the Intel SGX Root CA");
        assert!(matches!(authenticated.tee(), IntelTee::Tdx));
        assert!(matches!(authenticated.pck_ca_type(), PckCaType::Platform));
        assert_eq!(
            authenticated.root_ca_crl_distribution_point(),
            Some("https://certificates.trustedservices.intel.com/IntelSGXRootCA.der")
        );

        // The same quote must not verify against any other root.
        let other_root = pki::cert("Intel SGX Root CA", None, true);
        assert!(matches!(
            AuthenticatedQuote::new(&quote, &anchor_of(&other_root)),
            Err(AuthenticationError::PckChain(_))
        ));

        // Any change to the signed header and body breaks the quote signature.
        let mut tampered = quote.clone();
        tampered[48] ^= 1;
        assert!(matches!(
            AuthenticatedQuote::new(&tampered, &TrustAnchor::INTEL_SGX_ROOT_CA),
            Err(AuthenticationError::QuoteSignature)
        ));
    }

    #[test]
    fn revocation_verifies_crls_against_trust_anchor() {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let processor_ca = pki::cert("Intel SGX PCK Processor CA", Some(&root), true);
        let pck_crl_chain = chain_pem(&processor_ca, &root);
        let root_ca_crl = pki::crl(&root, &[]);
        let pck_crl = pki::crl(&processor_ca, &[]);
        let data = RevocationData {
            root_ca_crl: &root_ca_crl,
            pck_crl: &pck_crl,
            pck_crl_issuer_chain: &pck_crl_chain,
        };

        let revocation = Revocation::verify(&data, &anchor_of(&root)).unwrap();
        assert_eq!((revocation.root_ca_crl_num, revocation.pck_crl_num), (1, 1));
        assert_eq!(revocation.pck_crl_ca, CertRole::PckProcessorCa);
        assert!(!revocation.validity.expired(&Utc::now()));

        // CRLs must chain up to the trust anchor they're verified against.
        let other_root = pki::cert("Intel SGX Root CA", None, true);
        assert!(matches!(
            Revocation::verify(&data, &anchor_of(&other_root)),
            Err(RevocationError::RootCaCrl(_))
        ));
    }

    #[test]
    fn endorsements_verify_against_trust_anchor() {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let tcb_signer = pki::cert("Intel SGX TCB Signing", Some(&root), false);
        let tcb_chain = chain_pem(&tcb_signer, &root);
        let tcb_info = signed_tcb_info(&tcb_signer, "TDX", 3);
        let qe_identity = signed_qe_identity(&tcb_signer, "TD_QE", 2);
        let data = EndorsementData {
            tcb_info: &tcb_info,
            tcb_info_issuer_chain: &tcb_chain,
            qe_identity: &qe_identity,
            qe_identity_issuer_chain: &tcb_chain,
        };

        let endorsements = Endorsements::verify(&data, &anchor_of(&root)).unwrap();
        assert!(!endorsements.is_sgx);
        assert_eq!(endorsements.tcb_info.id, "TDX");
        assert_eq!(endorsements.qe_identity.id, "TD_QE");
        assert!(!endorsements.validity.expired(&Utc::now()));

        // Endorsements must chain up to the trust anchor they're verified against.
        let other_root = pki::cert("Intel SGX Root CA", None, true);
        assert!(matches!(
            Endorsements::verify(&data, &anchor_of(&other_root)),
            Err(EndorsementError::TcbInfo(_))
        ));

        // A TDX TCB Info with an SGX QE Identity is inconsistent.
        let sgx_qe_identity = signed_qe_identity(&tcb_signer, "QE", 2);
        let mismatched = EndorsementData {
            qe_identity: &sgx_qe_identity,
            ..data
        };
        assert!(matches!(
            Endorsements::verify(&mismatched, &anchor_of(&root)),
            Err(EndorsementError::QeIdentity(_))
        ));
    }

    #[test]
    fn root_ca_crl_must_be_issued_by_trust_anchor() {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let other = pki::cert("some other CA", None, true);

        let crl_der = pki::crl(&other, &[]);
        let err = verify_root_ca_crl(&crl_der, &anchor_of(&root), &mut Validity::new())
            .err()
            .expect("CRL signed by another key must be rejected");
        assert!(
            err.to_string()
                .contains("Root CA CRL signature verification failed"),
            "{err}"
        );
    }

    #[rstest::rstest]
    #[case::listed(true)]
    #[case::not_listed(false)]
    fn root_ca_crl_revokes_listed_intermediate(#[case] listed: bool) {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let intermediate = pki::cert("Intel SGX PCK Processor CA", Some(&root), true);
        let other_a = pki::cert("Intel SGX PCK Platform CA", Some(&root), true);
        let other_b = pki::cert("Intel SGX PCK Processor CA", Some(&root), true);

        let mut revoked = vec![other_a.serial(), other_b.serial()];
        if listed {
            revoked.push(intermediate.serial());
        }
        let revoked: Vec<&[u8]> = revoked.iter().map(Vec::as_slice).collect();
        let crl_der = pki::crl(&root, &revoked);

        let mut validity = Validity::new();
        let crl = verify_root_ca_crl(&crl_der, &anchor_of(&root), &mut validity).unwrap();
        assert_eq!(crl.crl_number().unwrap(), 1);
        assert!(!validity.expired(&Utc::now()));

        let res = check_not_revoked(
            &crl,
            &cert_of(&intermediate),
            "PCK intermediate CA certificate",
        );
        match listed {
            true => assert!(
                res.unwrap_err()
                    .to_string()
                    .contains("PCK intermediate CA certificate is revoked")
            ),
            false => res.unwrap(),
        }
    }

    #[rstest::rstest]
    #[case::listed(true)]
    #[case::not_listed(false)]
    fn pck_crl_revokes_listed_leaf(#[case] listed: bool) {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let processor_ca = pki::cert("Intel SGX PCK Processor CA", Some(&root), true);
        let leaf = pki::cert("Intel SGX PCK Certificate", Some(&processor_ca), false);
        let other_a = pki::cert("Intel SGX PCK Certificate", Some(&processor_ca), false);
        let other_b = pki::cert("Intel SGX PCK Certificate", Some(&processor_ca), false);

        let mut revoked = vec![other_a.serial(), other_b.serial()];
        if listed {
            revoked.push(leaf.serial());
        }
        let revoked: Vec<&[u8]> = revoked.iter().map(Vec::as_slice).collect();
        // The PCK CRL Issuer Chain is "PCK Processor CA Cert || Root CA
        // Cert" — the CA itself signs its own PCK CRL.
        let crl_der = pki::crl(&processor_ca, &revoked);
        let chain = chain_pem(&processor_ca, &root);

        let (crl, ca) =
            verify_pck_crl(&crl_der, &chain, &anchor_of(&root), &mut Validity::new()).unwrap();
        assert_eq!(ca, CertRole::PckProcessorCa);
        assert_eq!(crl.crl_number().unwrap(), 1);

        let res = check_not_revoked(&crl, &cert_of(&leaf), "PCK certificate");
        match listed {
            true => assert!(
                res.unwrap_err()
                    .to_string()
                    .contains("PCK certificate is revoked")
            ),
            false => res.unwrap(),
        }
    }

    #[test]
    fn pck_crl_issuer_chain_must_be_a_pck_ca() {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let tcb_signer = pki::cert("Intel SGX TCB Signing", Some(&root), false);

        let crl_der = pki::crl(&tcb_signer, &[]);
        let chain = chain_pem(&tcb_signer, &root);
        let err = verify_pck_crl(&crl_der, &chain, &anchor_of(&root), &mut Validity::new())
            .err()
            .expect("PCK CRL signed by a non-PCK CA must be rejected");
        assert!(
            err.to_string().contains("PCK CRL issuer chain signer"),
            "{err}"
        );
    }

    #[test]
    fn pck_crl_must_come_from_the_quotes_pck_ca() {
        check_pck_crl_issuer(CertRole::PckProcessorCa, CertRole::PckProcessorCa).unwrap();
        let err =
            check_pck_crl_issuer(CertRole::PckPlatformCa, CertRole::PckProcessorCa).unwrap_err();
        assert!(err.to_string().contains("PCK CRL was issued by"), "{err}");
    }

    #[rstest::rstest]
    #[case::tdx("TDX", 3, Some(false))]
    #[case::sgx("SGX", 3, Some(true))]
    #[case::v2("TDX", 2, None)]
    #[case::unknown_id("FOO", 3, None)]
    fn verify_tcb_info_checks_id_and_version(
        #[case] id: &str,
        #[case] version: u8,
        #[case] expected_is_sgx: Option<bool>,
    ) {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let signer = pki::cert("Intel SGX TCB Signing", Some(&root), false);
        let tcb_info = signed_tcb_info(&signer, id, version);

        let res = verify_tcb_info(
            &tcb_info,
            &chain_pem(&signer, &root),
            &anchor_of(&root),
            &mut Validity::new(),
        );
        match expected_is_sgx {
            Some(expected) => assert_eq!(res.unwrap().1, expected),
            None => assert!(res.is_err(), "TCB Info {id} v{version} must be rejected"),
        }
    }

    #[test]
    fn collateral_tee_must_match_quote() {
        check_tee(true, true).unwrap();
        check_tee(false, false).unwrap();
        for (collateral_is_sgx, quote_is_sgx) in [(true, false), (false, true)] {
            assert!(matches!(
                check_tee(collateral_is_sgx, quote_is_sgx),
                Err(AppraisalError::TeeMismatch { .. })
            ));
        }
    }

    #[rstest::rstest]
    #[case::tdx_v1("TD_QE", 1, false, false)]
    #[case::tdx_v2("TD_QE", 2, false, true)]
    #[case::sgx_v2("QE", 2, true, true)]
    #[case::sgx_qe_for_tdx("QE", 2, false, false)]
    fn verify_qe_identity_checks_id_and_version(
        #[case] id: &str,
        #[case] version: u8,
        #[case] is_sgx: bool,
        #[case] accepted: bool,
    ) {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let signer = pki::cert("Intel SGX TCB Signing", Some(&root), false);
        let qe_identity = signed_qe_identity(&signer, id, version);

        let res = verify_qe_identity(
            &qe_identity,
            &chain_pem(&signer, &root),
            &anchor_of(&root),
            is_sgx,
            &mut Validity::new(),
        );
        assert_eq!(res.is_ok(), accepted, "{:?}", res.err());

        if let Ok(identity) = res {
            // An all-zero QE Report body matches the all-zero identity.
            let qe_report_body = [0u8; 384].pread::<SgxReportBody>(0).unwrap();
            check_qe_report(&identity, &qe_report_body).unwrap();
        }
    }
}
