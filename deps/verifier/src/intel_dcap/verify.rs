use crate::intel_dcap::cert::{Cert, CertRole, Crl, Validity};
use crate::intel_dcap::claims::format_rfc3339;
use crate::intel_dcap::collateral_service::*;
use crate::intel_dcap::pck::PlatformInfo;
use crate::intel_dcap::quote::{parse_quote, QeCertificationData, Quote, SgxReportBody};
use crate::intel_dcap::tcb_status;
use anyhow::{anyhow, bail, Context};
use chrono::{DateTime, Utc};
use scroll::Pread;
use serde_json::{Map, Number, Value};
use tracing::debug;

const INTEL_PCS_ROOT_CA_PEM: &[u8] =
    include_bytes!("Intel_SGX_Provisioning_Certification_RootCA.pem");

// From CertType=5 ("PCK Leaf Cert || Intermediate CA Cert || Root CA Cert") we get:
const PCK_LEAF: usize = 0;
const INTERMEDIATE_CA: usize = 1;
const ROOT_CA: usize = 2;

/// Determines the PCK CA type from the intermediate cert's Common Name,
/// returning both the [`CertRole`] (for chain validation) and the
/// [`PckCaType`] (for selecting which PCK CRL to fetch).
fn pck_ca_type(intermediate: &Cert) -> anyhow::Result<(CertRole, PckCaType)> {
    if intermediate.is_common_name(CertRole::PckPlatformCa.common_name()) {
        return Ok((CertRole::PckPlatformCa, PckCaType::Platform));
    }
    if intermediate.is_common_name(CertRole::PckProcessorCa.common_name()) {
        return Ok((CertRole::PckProcessorCa, PckCaType::Processor));
    }
    bail!(
        "PCK intermediate CA cert has unexpected Common Name, expected \"{}\" or \"{}\", got {:?}",
        CertRole::PckPlatformCa.common_name(),
        CertRole::PckProcessorCa.common_name(),
        intermediate.common_name(),
    )
}

/// Validates a PCS-issued signing chain (as returned in the `*-Issuer-Chain` response
/// headers): exactly 2 certificates — the signer (with the expected Common Name for
/// `leaf_role`) and its declared root CA, itself anchored at the pinned `root`.
///
/// Returns the signer cert (the certificate whose public key verifies the response body).
fn verify_issuer_chain<'a>(
    chain: &'a [Cert],
    leaf_role: CertRole,
    root: &Cert,
    context_label: &str,
) -> anyhow::Result<&'a Cert> {
    let [signer, response_root] = chain else {
        bail!(
            "{context_label} issuer chain must contain exactly 2 certificates (signer, root CA), got {}",
            chain.len()
        );
    };
    signer
        .validate(leaf_role, response_root)
        .with_context(|| format!("{context_label} issuer chain signer"))?;
    response_root
        .validate(CertRole::RootCa, root)
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
    tcb_info: &'a TcbInfo,
) -> anyhow::Result<Option<&'a TcbLevel>> {
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

/// Loads the pinned Intel PCS root CA and the quote's own embedded 3-cert PCK
/// chain (leaf, intermediate CA, root CA), verifies the QE Report's ECDSA
/// signature against the leaf, and validates the chain up to the pinned
/// root. Returns `(root, pck_certificates, ca_role, ca_kind)` — `ca_role`/
/// `ca_kind` (the PCK CA type, Platform vs Processor) are determined once
/// here from the intermediate's Common Name, since they're needed both for
/// chain validation and to pick which PCK CRL to fetch later.
fn load_and_validate_pck_chain(
    qe_cert_data: &QeCertificationData,
) -> anyhow::Result<(Cert, Vec<Cert>, CertRole, PckCaType)> {
    let root = Cert::chain_from_pem(INTEL_PCS_ROOT_CA_PEM, 1)
        .context("failed to parse pinned Intel PCS root CA")?
        .into_iter()
        .next()
        .expect("chain_from_pem(_, 1) guarantees exactly one cert");

    let pck_certificates = Cert::chain_from_pem(qe_cert_data.certificates, 3).context(
        "PCK certificate chain must contain exactly 3 certificates (leaf, intermediate CA, root CA)",
    )?;

    if !pck_certificates[PCK_LEAF].verify_message(
        &qe_cert_data.qe_report.report,
        &qe_cert_data.qe_report.sig_r,
        &qe_cert_data.qe_report.sig_s,
    )? {
        bail!("QE Report ECDSA signature verification failed.");
    }

    // Determine the PCK CA type once from the intermediate cert's Common
    // Name; used both for chain validation below and to pick which PCK CRL
    // to fetch later.
    let (ca_role, ca_kind) = pck_ca_type(&pck_certificates[INTERMEDIATE_CA])?;

    // Sanity-check that the quote's own embedded root cert is internally
    // well-formed (self-signed, with the expected Common Name). This says
    // nothing about trust on its own — see the pinned-root anchoring below.
    pck_certificates[ROOT_CA]
        .validate(CertRole::RootCa, &pck_certificates[ROOT_CA])
        .context("PCK root CA certificate is not self-signed with the expected identity")?;

    // Certificate/CRL expiration is checked explicitly below (matching upstream
    // DCAP QVL/QvE semantics, where expired-but-otherwise-valid collateral is
    // non-fatal and surfaced via the `collateral_expiration_status` claim), so
    // chain verification itself does not enforce validity periods.
    //
    // Trust is anchored at `root` (the pinned Intel PCS root CA), never at
    // `pck_certificates[ROOT_CA]`'s own self-declared key: that cert is
    // attacker-controlled input embedded in the quote, so it can only be used
    // for the self-signature sanity check above, not as a verification key.
    pck_certificates[INTERMEDIATE_CA].validate(ca_role, &root)?;
    pck_certificates[PCK_LEAF].validate(CertRole::PckLeaf, &pck_certificates[INTERMEDIATE_CA])?;

    Ok((root, pck_certificates, ca_role, ca_kind))
}

/// Fetches the QE Identity collateral, verifies its issuer chain up to the
/// pinned `root` and its signature, then checks its content (id, miscselect,
/// attributes, mrsigner, isvprodid) against the quote's own QE Report. Returns
/// the deserialized collateral — the caller still needs it to look up the
/// matching TCB level by ISV SVN, which requires borrowing from it, so that
/// lookup can't happen in here without fighting the borrow checker — and the
/// Root CA CRL distribution point declared by the QE Identity's own TCB
/// Signing cert, needed to fetch the Root CA CRL next.
async fn verify_qe_identity(
    collateral: &impl CollateralService,
    tee: &IntelTee,
    root: &Cert,
    is_sgx: bool,
    qe_report_body: &SgxReportBody,
    validity: &mut Validity,
    now: &DateTime<Utc>,
) -> anyhow::Result<(QeIdentity, Option<String>)> {
    let CollateralData {
        body: raw_qe_identity,
        cert_chain: qe_identity_chain,
    } = collateral
        .get(CollateralType::QeIdentity(tee))
        .await
        .context("failed to fetch QE Identity collateral")?;

    let qe_identity_cert_chain = Cert::chain_from_pem(
        &qe_identity_chain.context("QE Identity collateral response is missing its issuer chain")?,
        2,
    )?;

    let qe_identity_signer = verify_issuer_chain(
        &qe_identity_cert_chain,
        CertRole::TcbSigning,
        root,
        "QE Identity",
    )?;

    let qe_identity_root = &qe_identity_cert_chain[1];
    validity.observe_cert(qe_identity_signer, now);
    validity.observe_cert(qe_identity_root, now);

    let qe_identity: QeIdentity = serde_json::from_slice(raw_qe_identity.as_slice())
        .context("failed to deserialize QE Identity collateral")?;

    // TODO: this re-serializes the deserialized struct instead of slicing the
    // exact `enclaveIdentity` bytes out of `raw_qe_identity`. Intel signs the
    // original response bytes, so a round-trip that isn't byte-identical
    // (field order, spacing, escaping) would break verification; capture the
    // raw signed substring (e.g. via `serde_json::RawValue`) instead.
    let enclave_identity_bytes = serde_json::to_vec(&qe_identity.enclave_identity)
        .context("failed to re-serialize QE Identity for signature verification")?;

    if !qe_identity_signer.verify_message(
        &enclave_identity_bytes,
        &qe_identity.signature[..32],
        &qe_identity.signature[32..],
    )? {
        bail!("QE Identity ECDSA signature verification failed.");
    }

    let expected_qe_id = if is_sgx { "QE" } else { "TD_QE" };
    if qe_identity.enclave_identity.id != expected_qe_id {
        bail!(
            "unexpected QE Identity id, expected \"{expected_qe_id}\", got \"{}\"",
            qe_identity.enclave_identity.id
        );
    }

    let flags_mask: [u8; 8] = qe_identity.enclave_identity.attributes_mask[..8].try_into()?;
    let flags: [u8; 8] = qe_identity.enclave_identity.attributes[..8].try_into()?;

    let xfrm_mask: [u8; 8] = qe_identity.enclave_identity.attributes_mask[8..].try_into()?;
    let xfrm: [u8; 8] = qe_identity.enclave_identity.attributes[8..].try_into()?;

    if (u32::from_le_bytes(qe_report_body.misc_select)
        & u32::from_le_bytes(*qe_identity.enclave_identity.miscselect_mask))
        != u32::from_le_bytes(*qe_identity.enclave_identity.miscselect)
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
    if *qe_identity.enclave_identity.mrsigner != qe_report_body.mr_signer {
        bail!("QE Report mrsigner does not match QE Identity");
    }
    if qe_identity.enclave_identity.isvprodid != u16::from_le_bytes(qe_report_body.isv_prod_id) {
        bail!("QE Report isvprodid does not match QE Identity");
    }

    validity.observe_deadline(&qe_identity.enclave_identity.next_update, now);

    let root_ca_crl_dp = qe_identity_cert_chain[0].crl_distribution_point();

    Ok((qe_identity, root_ca_crl_dp))
}

/// Fetches the Root CA CRL, verifies it was issued by the pinned `root`
/// (never the quote's own embedded root cert — see [`load_and_validate_pck_chain`]),
/// and checks `intermediate` (the PCK intermediate CA) isn't revoked by it.
async fn check_root_ca_crl(
    collateral: &impl CollateralService,
    root: &Cert,
    crl_dp: Option<&str>,
    intermediate: &Cert,
    validity: &mut Validity,
    now: &DateTime<Utc>,
) -> anyhow::Result<Crl> {
    let CollateralData {
        body: raw_root_ca_crl,
        ..
    } = collateral
        .get(CollateralType::RootCaCrl(crl_dp))
        .await
        .context("failed to fetch Root CA CRL collateral")?;

    let root_ca_crl = Crl::from_der(&raw_root_ca_crl)?;
    if !root_ca_crl.is_issued_by(root)? {
        bail!("Root CA CRL signature verification failed");
    }
    if root_ca_crl.is_revoked(intermediate.serial_number()) {
        bail!("PCK intermediate CA certificate is revoked");
    }

    validity.observe_crl(&root_ca_crl, now);

    Ok(root_ca_crl)
}

/// Fetches the PCK CRL for `ca_kind`, verifies its issuer chain up to the
/// pinned `root`, and checks `leaf` (the PCK leaf cert) isn't revoked by it.
async fn check_pck_crl(
    collateral: &impl CollateralService,
    ca_kind: PckCaType,
    ca_role: CertRole,
    root: &Cert,
    leaf: &Cert,
    validity: &mut Validity,
    now: &DateTime<Utc>,
) -> anyhow::Result<Crl> {
    let CollateralData {
        body: pck_crl_der_bytes,
        cert_chain: raw_pck_crl_chain,
    } = collateral
        .get(CollateralType::PckCrl(ca_kind))
        .await
        .context("failed to fetch PCK CRL collateral")?;

    let pck_crl = Crl::from_der(&pck_crl_der_bytes)?;

    let pck_crl_cert_chain = Cert::chain_from_pem(
        &raw_pck_crl_chain.context("PCK CRL collateral response is missing its issuer chain")?,
        2,
    )?;
    let pck_crl_signer = verify_issuer_chain(&pck_crl_cert_chain, ca_role, root, "PCK CRL")?;

    if !pck_crl.is_issued_by(pck_crl_signer)? {
        bail!("PCK CRL signature verification failed");
    }

    if pck_crl.is_revoked(leaf.serial_number()) {
        bail!("PCK certificate is revoked");
    }

    validity.observe_crl(&pck_crl, now);

    Ok(pck_crl)
}

/// Fetches the TCB Info collateral for the platform's FMSPC, checks its
/// FMSPC/PCEID match the PCK certificate's, verifies its issuer chain up to
/// the pinned `root`, and verifies its signature.
async fn verify_tcb_info_collateral(
    collateral: &impl CollateralService,
    tee: &IntelTee,
    platform_info: &PlatformInfo,
    root: &Cert,
    validity: &mut Validity,
    now: &DateTime<Utc>,
) -> anyhow::Result<TcbInfoJson> {
    let CollateralData {
        body: raw_tcb_info,
        cert_chain: raw_tcb_cert_chain,
    } = collateral
        .get(CollateralType::TcbInfo(tee, platform_info.fmspc))
        .await
        .context("failed to fetch TCB Info collateral")?;

    let tcb_cert_chain = Cert::chain_from_pem(
        &raw_tcb_cert_chain.context("TCB Info collateral response is missing its issuer chain")?,
        2,
    )?;
    let tcb_info_json: TcbInfoJson = serde_json::from_slice(raw_tcb_info.as_slice())
        .context("failed to deserialize TCB Info collateral")?;

    if *tcb_info_json.tcb_info.fmspc != platform_info.fmspc {
        bail!("TCB Info FMSPC does not match PCK certificate FMSPC");
    }
    if *tcb_info_json.tcb_info.pce_id != platform_info.pceid {
        bail!("TCB Info PCEID does not match PCK certificate PCEID");
    }

    // TODO: this re-serializes the deserialized struct instead of slicing the
    // exact `tcbInfo` bytes out of `raw_tcb_info`. Intel signs the original
    // response bytes, so a round-trip that isn't byte-identical (field order,
    // spacing, escaping) would break verification; capture the raw signed
    // substring (e.g. via `serde_json::RawValue`) instead.
    let tcb_info_bytes = serde_json::to_vec(&tcb_info_json.tcb_info)
        .context("failed to re-serialize TCB Info for signature verification")?;

    let tcb_info_signer = verify_issuer_chain(&tcb_cert_chain, CertRole::TcbSigning, root, "TCB Info")?;

    let tcb_info_root = &tcb_cert_chain[1];
    validity.observe_cert(tcb_info_signer, now);
    validity.observe_cert(tcb_info_root, now);
    validity.observe_deadline(&tcb_info_json.tcb_info.next_update, now);

    if !tcb_info_signer.verify_message(
        &tcb_info_bytes,
        &tcb_info_json.signature[..32],
        &tcb_info_json.signature[32..],
    )? {
        bail!("TCB Info ECDSA signature verification failed.");
    }

    Ok(tcb_info_json)
}

/// The values every verification phase contributes toward the final claims
/// map — plain data, not itself part of the verification logic, so it's
/// bundled into one struct rather than passed as individually-named
/// parameters.
struct ClaimsInput<'a> {
    validity: &'a Validity,
    tcb_date: DateTime<Utc>,
    tcb_eval_num: u32,
    pck_crl_num: u32,
    root_ca_crl_num: u32,
    root_key_id: String,
    platform_info: &'a PlatformInfo,
    tcb_status: TcbStatus,
    advisory_ids: std::collections::BTreeSet<String>,
}

fn build_claims(input: ClaimsInput) -> anyhow::Result<Map<String, Value>> {
    let mut claims_map = Map::new();
    claims_map.insert(
        "earliest_issue_date".to_string(),
        Value::String(format_rfc3339(input.validity.earliest_issue_date())?),
    );
    claims_map.insert(
        "latest_issue_date".to_string(),
        Value::String(format_rfc3339(input.validity.latest_issue_date())?),
    );
    claims_map.insert(
        "earliest_expiration_date".to_string(),
        Value::String(format_rfc3339(input.validity.earliest_expiration_date())?),
    );
    claims_map.insert(
        "tcb_date".to_string(),
        Value::String(format_rfc3339(input.tcb_date.timestamp())?),
    );
    claims_map.insert(
        "pck_crl_num".to_string(),
        Value::from(Number::from(input.pck_crl_num)),
    );
    claims_map.insert(
        "root_ca_crl_num".to_string(),
        Value::from(Number::from(input.root_ca_crl_num)),
    );
    claims_map.insert(
        "tcb_eval_num".to_string(),
        Value::from(Number::from(input.tcb_eval_num)),
    );
    claims_map.insert(
        "platform_provider_id".to_string(),
        Value::String(hex::encode(input.platform_info.ppid)),
    );
    claims_map.insert(
        "sgx_type".to_string(),
        Value::String(match input.platform_info.sgx_type {
            0 => "Standard".to_string(),
            1 => "Scalable".to_string(),
            2 => "Scalable with Integrity".to_string(),
            other => format!("Unknown ({other})"),
        }),
    );
    if let Some(dynamic_platform) = input.platform_info.dynamic_platform {
        claims_map.insert(
            "is_dynamic_platform".to_string(),
            Value::Bool(dynamic_platform),
        );
    }
    if let Some(cached_keys) = input.platform_info.cached_keys {
        claims_map.insert("is_cached_keys".to_string(), Value::Bool(cached_keys));
    }
    if let Some(smt_enabled) = input.platform_info.smt_enabled {
        claims_map.insert("is_smt_enabled".to_string(), Value::Bool(smt_enabled));
    }
    claims_map.insert("root_key_id".to_string(), Value::String(input.root_key_id));
    claims_map.insert(
        "tcb_status".to_string(),
        Value::String(input.tcb_status.to_string()),
    );
    claims_map.insert(
        "collateral_expiration_status".to_string(),
        Value::String((input.validity.expired() as u8).to_string()),
    );
    claims_map.insert(
        "advisory_ids".to_string(),
        Value::Array(input.advisory_ids.into_iter().map(Value::String).collect()),
    );

    Ok(claims_map)
}

/// Verifies an SGX or TDX DCAP quote and its collateral chain, returning
/// claims derived from the supplemental data on success.
pub async fn dcap_verify(
    quote: &[u8],
    now: &DateTime<Utc>,
    collateral: &impl CollateralService,
) -> anyhow::Result<Map<String, Value>> {
    let parsed_quote = parse_quote(quote)?;
    // `parse_quote` only ever pairs version 3 with SGX and versions 4/5 with
    // TDX (see its own dispatch), so the quote variant already determines this.
    let is_sgx = matches!(parsed_quote, Quote::V3 { .. });
    let tee = if is_sgx { IntelTee::Sgx } else { IntelTee::Tdx };

    let cert_data = parsed_quote.cert_data();

    if !parsed_quote.verify_ak_signature(quote)? {
        bail!("Quote ECDSA signature verification failed.");
    }

    // Test that the AK pubkey and QE authentication data are bound to
    // Quoting Enclave's Report Data:
    // sha256(Attestation Key || QE Authentication Data) || 32-0x00’s
    let qe_report_body = (cert_data.qe_certification_data.qe_report.report)
        .pread::<SgxReportBody>(0)
        .map_err(|e| anyhow!("failed to parse QE report body: {e}"))?;

    if !parsed_quote.verify_qe_report_data_binding(&qe_report_body.report_data) {
        bail!("QE Report ReportData mismatch");
    }

    let (root, pck_certificates, ca_role, ca_kind) =
        load_and_validate_pck_chain(&cert_data.qe_certification_data)?;

    let mut validity = Validity::new();
    validity.observe_cert(&pck_certificates[ROOT_CA], now);
    validity.observe_cert(&pck_certificates[INTERMEDIATE_CA], now);
    validity.observe_cert(&pck_certificates[PCK_LEAF], now);

    let (qe_identity, root_ca_crl_dp) = verify_qe_identity(
        collateral,
        &tee,
        &root,
        is_sgx,
        &qe_report_body,
        &mut validity,
        now,
    )
    .await?;

    let qe_tcb_level = tcb_status::find_tcb_level_by_isvsvn(
        &qe_identity.enclave_identity.tcb_levels,
        u16::from_le_bytes(qe_report_body.isv_svn),
    )
    .context("no matching QE Identity TCB level found for QE Report isvsvn")?;

    debug!("QE TCB level: {:?}", qe_tcb_level.tcb_status);

    let root_ca_crl = check_root_ca_crl(
        collateral,
        &root,
        root_ca_crl_dp.as_deref(),
        &pck_certificates[INTERMEDIATE_CA],
        &mut validity,
        now,
    )
    .await?;

    let pck_crl = check_pck_crl(
        collateral,
        ca_kind,
        ca_role,
        &root,
        &pck_certificates[PCK_LEAF],
        &mut validity,
        now,
    )
    .await?;

    let platform_info =
        pck_certificates[PCK_LEAF].platform_info(ca_role == CertRole::PckPlatformCa)?;

    let tcb_info_json =
        verify_tcb_info_collateral(collateral, &tee, &platform_info, &root, &mut validity, now)
            .await?;

    // Go over the sorted collection of TCB Levels retrieved from
    // TCB Info starting from the first item on the list:
    // Step 3.c (TD Report TEE TCB SVNs) is TDX-only; `parsed_quote.tcb_svn()`
    // means something else entirely for SGX (it's `cpu_svn`, already covered
    // by `platform_info.tcb_components`/`pcesvn` above), so it doesn't apply.
    let td_svns: Option<&[u8]> = if is_sgx {
        None
    } else {
        Some(parsed_quote.tcb_svn())
    };
    let tcb_level = tcb_status::find_matching_tcb_level(
        &tcb_info_json.tcb_info.tcb_levels,
        &platform_info.tcb_components,
        platform_info.pcesvn,
        td_svns,
    )?;

    let tdx_module_level = tdx_module_tcb_level(is_sgx, &parsed_quote, &tcb_info_json.tcb_info)?;

    let tcb_status = tcb_status::converge(
        tcb_level.tcb_status,
        tdx_module_level.map(|l| l.tcb_status),
        qe_tcb_level.tcb_status,
        parsed_quote.tee_tcb_svn2(),
        &tcb_info_json.tcb_info,
    )?;

    debug!("converged tcb_status: {tcb_status}");

    let advisory_ids = tcb_status::merge_advisory_ids(tcb_level, qe_tcb_level, tdx_module_level);

    let tcb_date = tcb_level.tcb_date.min(qe_tcb_level.tcb_date);
    let tcb_eval_num = tcb_info_json
        .tcb_info
        .tcb_evaluation_data_number
        .min(qe_identity.enclave_identity.tcb_evaluation_data_number);

    let pck_crl_num = pck_crl.crl_number()?;
    let root_ca_crl_num = root_ca_crl.crl_number()?;
    let root_key_id = hex::encode(pck_certificates[ROOT_CA].key_id()?);

    build_claims(ClaimsInput {
        validity: &validity,
        tcb_date,
        tcb_eval_num,
        pck_crl_num,
        root_ca_crl_num,
        root_key_id,
        platform_info: &platform_info,
        tcb_status,
        advisory_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// Exercises the cert type/CN validation in `dcap_verify` against real Intel PCS
    /// collateral. Requires network access to `api.trustedservices.intel.com`.
    #[cfg(target_arch = "x86_64")]
    #[tokio::test]
    #[ignore = "requires PCS network connectivity; run with: cargo test -p verifier --no-default-features --features tdx-verifier -- dcap_verify_tdx_quote --include-ignored"]
    async fn dcap_verify_tdx_quote() {
        use crate::intel_dcap::QcnlConfig;
        use std::fs;

        let quote_bin = fs::read("./test_data/tdx_quote_4.dat").unwrap();
        let pcs = QcnlConfig::default().pcs().expect("Pcs::new");

        let res = dcap_verify(&quote_bin, &Utc::now(), &pcs).await;
        assert!(res.is_ok(), "{res:?}");
    }

    /// Exercises the SGX (quote v3) path through `dcap_verify` — QE Identity
    /// `id` == "QE" (not "TD_QE"), no TDX Module Identity checks, no TEE TCB
    /// SVN step 3.c. Requires network access to `api.trustedservices.intel.com`.
    #[cfg(target_arch = "x86_64")]
    #[tokio::test]
    #[ignore = "requires PCS network connectivity; run with: cargo test -p verifier --no-default-features --features tdx-verifier -- dcap_verify_sgx_quote --include-ignored"]
    async fn dcap_verify_sgx_quote() {
        use crate::intel_dcap::QcnlConfig;
        use std::fs;

        let quote_bin = fs::read("./test_data/occlum_quote.dat").unwrap();
        let pcs = QcnlConfig::default().pcs().expect("Pcs::new");

        let res = dcap_verify(&quote_bin, &Utc::now(), &pcs).await;
        assert!(res.is_ok(), "{res:?}");
    }

    /// Exercises the Root CA CRL fetch/verification against Alibaba's PCCS
    /// mirror, which returns the Root CA CRL as hex-ASCII text over HTTP
    /// rather than raw DER — `Pcs::get` must normalize this so `dcap_verify`
    /// (which expects `CollateralService::get` to always return raw DER)
    /// still succeeds. Requires network access to Alibaba's PCCS.
    #[cfg(target_arch = "x86_64")]
    #[tokio::test]
    #[ignore = "requires PCS network connectivity; run with: cargo test -p verifier --no-default-features --features tdx-verifier -- dcap_verify_tdx_quote_5_alibaba_pcs --include-ignored"]
    async fn dcap_verify_tdx_quote_5_alibaba_pcs() {
        use crate::intel_dcap::QcnlConfig;
        use std::fs;

        let quote_bin = fs::read("./test_data/tdx_quote_5.dat").unwrap();
        let config: QcnlConfig = serde_json::from_value(serde_json::json!({
            "collateral_service": "https://sgx-dcap-server.cn-beijing.aliyuncs.com/sgx/certification/v4/"
        }))
        .expect("deserialize QcnlConfig");
        let pcs = config.pcs().expect("Pcs::new");

        let res = dcap_verify(&quote_bin, &Utc::now(), &pcs).await;
        assert!(res.is_ok(), "{res:?}");
    }

    /// A `CollateralService` test double: returns pre-configured, in-memory
    /// responses instead of making network calls. This is what makes the
    /// collateral-fetching helper functions below (`check_root_ca_crl`,
    /// `check_pck_crl`, ...) unit-testable at all — they all take a
    /// `collateral: &impl CollateralService`, and until this existed, the
    /// only implementation of that trait (`Pcs`) required real network
    /// access, so failure paths like "cert is revoked" or "CRL signature is
    /// wrong" had no fast, isolated test coverage.
    #[derive(Default)]
    struct MockCollateral {
        root_ca_crl: Option<CollateralData>,
        pck_crl: Option<CollateralData>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("mock collateral service has no response configured for this request")]
    struct MockCollateralError;

    impl CollateralService for MockCollateral {
        type Error = MockCollateralError;

        async fn get(&self, ct: CollateralType<'_>) -> Result<CollateralData, MockCollateralError> {
            let data = match ct {
                CollateralType::RootCaCrl(_) => &self.root_ca_crl,
                CollateralType::PckCrl(_) => &self.pck_crl,
                CollateralType::TcbInfo(..) | CollateralType::QeIdentity(_) => &None,
            };
            data.clone().ok_or(MockCollateralError)
        }
    }

    /// Minimal DCAP-shaped PKI, built with `openssl`, for exercising
    /// `check_root_ca_crl`/`check_pck_crl` against certs/CRLs whose content
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
        use openssl::x509::{X509CrlBuilder, X509Extension, X509NameBuilder, X509RevokedBuilder, X509};

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
                let bc = BasicConstraints::new().ca().build().expect("BasicConstraints");
                builder.append_extension(bc).expect("append BasicConstraints");
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
            builder
                .set_last_update(&now)
                .expect("set lastUpdate");
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

        /// A serial number distinguishable from the other test certs'.
        fn rand_serial() -> u32 {
            use std::sync::atomic::{AtomicU32, Ordering};
            static NEXT: AtomicU32 = AtomicU32::new(1);
            NEXT.fetch_add(1, Ordering::Relaxed)
        }
    }

    #[tokio::test]
    async fn check_root_ca_crl_bails_when_signature_invalid() {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let other = pki::cert("some other CA", None, true);
        let intermediate = pki::cert("Intel SGX PCK Processor CA", Some(&root), true);

        // CRL is signed by `other`, not `root` — `is_issued_by(&root)` must fail.
        let crl_der = pki::crl(&other, &[]);
        let collateral = MockCollateral {
            root_ca_crl: Some(CollateralData {
                body: crl_der,
                cert_chain: None,
            }),
            ..Default::default()
        };

        let root_cert = Cert::chain_from_pem(&root.pem(), 1).unwrap().remove(0);
        let intermediate_cert = Cert::chain_from_pem(&intermediate.pem(), 1).unwrap().remove(0);
        let mut validity = Validity::new();

        let err = check_root_ca_crl(
            &collateral,
            &root_cert,
            None,
            &intermediate_cert,
            &mut validity,
            &Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("Root CA CRL signature verification failed"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn check_root_ca_crl_bails_when_intermediate_is_revoked() {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let intermediate = pki::cert("Intel SGX PCK Processor CA", Some(&root), true);

        let crl_der = pki::crl(&root, &[&intermediate.serial()]);
        let collateral = MockCollateral {
            root_ca_crl: Some(CollateralData {
                body: crl_der,
                cert_chain: None,
            }),
            ..Default::default()
        };

        let root_cert = Cert::chain_from_pem(&root.pem(), 1).unwrap().remove(0);
        let intermediate_cert = Cert::chain_from_pem(&intermediate.pem(), 1).unwrap().remove(0);
        let mut validity = Validity::new();

        let err = check_root_ca_crl(
            &collateral,
            &root_cert,
            None,
            &intermediate_cert,
            &mut validity,
            &Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("PCK intermediate CA certificate is revoked"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn check_pck_crl_bails_when_leaf_is_revoked() {
        let root = pki::cert("Intel SGX Root CA", None, true);
        let processor_ca = pki::cert("Intel SGX PCK Processor CA", Some(&root), true);
        let leaf = pki::cert("Intel SGX PCK Certificate", Some(&processor_ca), false);

        // The PCK CRL Issuer Chain is "PCK Processor CA Cert || Root CA
        // Cert" — the CA itself signs its own PCK CRL.
        let crl_der = pki::crl(&processor_ca, &[&leaf.serial()]);
        let mut cert_chain = processor_ca.pem();
        cert_chain.extend_from_slice(&root.pem());
        let collateral = MockCollateral {
            pck_crl: Some(CollateralData {
                body: crl_der,
                cert_chain: Some(cert_chain),
            }),
            ..Default::default()
        };

        let root_cert = Cert::chain_from_pem(&root.pem(), 1).unwrap().remove(0);
        let leaf_cert = Cert::chain_from_pem(&leaf.pem(), 1).unwrap().remove(0);
        let mut validity = Validity::new();

        let err = check_pck_crl(
            &collateral,
            PckCaType::Processor,
            CertRole::PckProcessorCa,
            &root_cert,
            &leaf_cert,
            &mut validity,
            &Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("PCK certificate is revoked"), "{err}");
    }

    #[tokio::test]
    async fn check_pck_crl_bails_when_issuer_chain_has_wrong_role() {
        let root = pki::cert("Intel SGX Root CA", None, true);
        // Signer has the wrong CN for `CertRole::PckProcessorCa` — should be
        // rejected by `verify_issuer_chain`'s `signer.validate(leaf_role, ..)`
        // before the CRL's own signature is ever checked.
        let wrong_role_signer = pki::cert("Intel SGX PCK Platform CA", Some(&root), true);

        let crl_der = pki::crl(&wrong_role_signer, &[]);
        let mut cert_chain = wrong_role_signer.pem();
        cert_chain.extend_from_slice(&root.pem());
        let collateral = MockCollateral {
            pck_crl: Some(CollateralData {
                body: crl_der,
                cert_chain: Some(cert_chain),
            }),
            ..Default::default()
        };

        let root_cert = Cert::chain_from_pem(&root.pem(), 1).unwrap().remove(0);
        let leaf = pki::cert("Intel SGX PCK Certificate", Some(&wrong_role_signer), false);
        let leaf_cert = Cert::chain_from_pem(&leaf.pem(), 1).unwrap().remove(0);
        let mut validity = Validity::new();

        let err = check_pck_crl(
            &collateral,
            PckCaType::Processor,
            CertRole::PckProcessorCa,
            &root_cert,
            &leaf_cert,
            &mut validity,
            &Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("PCK CRL issuer chain signer"), "{err}");
    }
}
