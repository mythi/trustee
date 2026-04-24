// Copyright (c) 2026 Confidential Containers Project Authors
//
// SPDX-License-Identifier: Apache-2.0

//! [`dcap_verify`]: DCAP quote verification against collateral fetched from a
//! [`CollateralService`], producing the verifier's claims.

use crate::intel_dcap::claims::format_rfc3339;
use crate::intel_dcap::collateral_service::{CollateralService, CollateralType};
use crate::intel_dcap::verify::{
    Appraisal, AuthenticatedQuote, EndorsementData, Endorsements, Revocation, RevocationData,
    TrustAnchor, TrustedQuote,
};
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde_json::{Map, Number, Value};

/// Verifies an SGX or TDX DCAP quote and its collateral against the Intel SGX
/// Root CA, fetching the collateral from `collateral`, and returns claims
/// derived from the supplemental data on success.
///
/// Collateral is only fetched for a quote that has passed the previous stage,
/// and only with keys taken from what that stage verified: the CRLs by the
/// quote's PCK CA, the endorsements by its TEE and FMSPC.
pub async fn dcap_verify(
    quote: &[u8],
    now: &DateTime<Utc>,
    collateral: &impl CollateralService,
) -> anyhow::Result<Map<String, Value>> {
    let root = TrustAnchor::INTEL_SGX_ROOT_CA;
    let quote = AuthenticatedQuote::new(quote, &root)?;

    let root_ca_crl = collateral
        .get(CollateralType::RootCaCrl(
            quote.root_ca_crl_distribution_point(),
        ))
        .await
        .context("failed to fetch Root CA CRL collateral")?;
    let pck_crl = collateral
        .get(CollateralType::PckCrl(quote.pck_ca_type()))
        .await
        .context("failed to fetch PCK CRL collateral")?;
    let revocation = Revocation::verify(
        &RevocationData {
            root_ca_crl: &root_ca_crl.body,
            pck_crl: &pck_crl.body,
            pck_crl_issuer_chain: pck_crl
                .cert_chain
                .as_deref()
                .context("PCK CRL collateral response is missing its issuer chain")?,
        },
        &root,
    )?;
    let quote = quote.check_revocation(&revocation)?;

    let tee = quote.tee();
    let qe_identity = collateral
        .get(CollateralType::QeIdentity(&tee))
        .await
        .context("failed to fetch QE Identity collateral")?;
    let tcb_info = collateral
        .get(CollateralType::TcbInfo(&tee, quote.platform_info().fmspc))
        .await
        .context("failed to fetch TCB Info collateral")?;
    let endorsements = Endorsements::verify(
        &EndorsementData {
            tcb_info: &tcb_info.body,
            tcb_info_issuer_chain: tcb_info
                .cert_chain
                .as_deref()
                .context("TCB Info collateral response is missing its issuer chain")?,
            qe_identity: &qe_identity.body,
            qe_identity_issuer_chain: qe_identity
                .cert_chain
                .as_deref()
                .context("QE Identity collateral response is missing its issuer chain")?,
        },
        &root,
    )?;
    let appraisal = endorsements.appraise(&quote)?;

    claims(&quote, &appraisal, now)
}

/// The verifier's claims for a verified quote.
fn claims(
    quote: &TrustedQuote<'_>,
    appraisal: &Appraisal<'_>,
    now: &DateTime<Utc>,
) -> anyhow::Result<Map<String, Value>> {
    let validity = &appraisal.validity;
    let platform_info = quote.platform_info();
    let mut claims_map = Map::new();
    claims_map.insert(
        "earliest_issue_date".to_string(),
        Value::String(format_rfc3339(validity.earliest_issue_date())?),
    );
    claims_map.insert(
        "latest_issue_date".to_string(),
        Value::String(format_rfc3339(validity.latest_issue_date())?),
    );
    claims_map.insert(
        "earliest_expiration_date".to_string(),
        Value::String(format_rfc3339(validity.earliest_expiration_date())?),
    );
    claims_map.insert(
        "tcb_date".to_string(),
        Value::String(format_rfc3339(appraisal.tcb_date.timestamp())?),
    );
    claims_map.insert(
        "pck_crl_num".to_string(),
        Value::from(Number::from(quote.pck_crl_num())),
    );
    claims_map.insert(
        "root_ca_crl_num".to_string(),
        Value::from(Number::from(quote.root_ca_crl_num())),
    );
    claims_map.insert(
        "tcb_eval_num".to_string(),
        Value::from(Number::from(appraisal.tcb_eval_num)),
    );
    claims_map.insert(
        "platform_provider_id".to_string(),
        Value::String(hex::encode(platform_info.ppid)),
    );
    claims_map.insert(
        "sgx_type".to_string(),
        Value::String(match platform_info.sgx_type {
            0 => "Standard".to_string(),
            1 => "Scalable".to_string(),
            2 => "Scalable with Integrity".to_string(),
            other => format!("Unknown ({other})"),
        }),
    );
    if let Some(dynamic_platform) = platform_info.dynamic_platform {
        claims_map.insert(
            "is_dynamic_platform".to_string(),
            Value::Bool(dynamic_platform),
        );
    }
    if let Some(cached_keys) = platform_info.cached_keys {
        claims_map.insert("is_cached_keys".to_string(), Value::Bool(cached_keys));
    }
    if let Some(smt_enabled) = platform_info.smt_enabled {
        claims_map.insert("is_smt_enabled".to_string(), Value::Bool(smt_enabled));
    }
    claims_map.insert(
        "root_key_id".to_string(),
        Value::String(hex::encode(quote.root_key_id())),
    );
    claims_map.insert(
        "tcb_status".to_string(),
        Value::String(appraisal.tcb_status.to_string()),
    );
    claims_map.insert(
        "collateral_expiration_status".to_string(),
        Value::String((appraisal.expired(now) as u8).to_string()),
    );
    claims_map.insert(
        "advisory_ids".to_string(),
        Value::Array(
            appraisal
                .advisory_ids
                .iter()
                .map(|id| Value::String((*id).to_owned()))
                .collect(),
        ),
    );

    Ok(claims_map)
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
}
