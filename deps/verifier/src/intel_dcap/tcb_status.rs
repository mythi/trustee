// Copyright (c) 2026 Confidential Containers Project Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Merges the TCB status of a TCB Info level, a TDX Module Identity level, and
//! a QE Identity level into the single "converged" `tcb_status` claim.
//!
//! Ported from Intel's DCAP QVL/QvE reference implementation:
//! - `QuoteVerification/QVL/Src/AttestationLibrary/src/Verifiers/Checks/TcbLevelCheck.cpp`
//!   (`convergeTcbStatusWithQeTcbStatus`)
//! - `QuoteVerification/QVL/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp`
//!   (`convergeTcbStatusWithTdxModuleStatus`)
//!
//! Both upstream functions apply the identical downgrade rule, just fed from a
//! different source (QE Identity vs. TDX Module Identity); [`downgrade`] is the
//! single shared implementation. The merge is downgrade-only: a worse status at
//! a later stage can only make the result worse, never better than what an
//! earlier stage already found.

use crate::intel_dcap::collateral_service::{HexBytes, TcbInfo, TcbLevel, TcbStatus, TdxModuleIdentity};
use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;

/// A three-way TCB status signal — derived from matching a QE Identity or TDX
/// Module Identity TCB level — that [`downgrade`] can apply to a base status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DowngradeSeverity {
    UpToDate,
    OutOfDate,
    Revoked,
}

impl DowngradeSeverity {
    fn from_status(status: &TcbStatus) -> Self {
        match status {
            TcbStatus::Revoked => DowngradeSeverity::Revoked,
            TcbStatus::UpToDate => DowngradeSeverity::UpToDate,
            _ => DowngradeSeverity::OutOfDate,
        }
    }
}

/// Downgrade `base` according to `severity`: `OutOfDate` can only push an
/// up-to-date-ish status down to `OutOfDate`/`OutOfDateConfigurationNeeded`,
/// `Revoked` always wins outright, and `UpToDate` leaves `base` unchanged.
/// `severity` can never *improve* on `base`.
fn downgrade(base: TcbStatus, severity: DowngradeSeverity) -> TcbStatus {
    match severity {
        DowngradeSeverity::UpToDate => base,
        DowngradeSeverity::Revoked => TcbStatus::Revoked,
        DowngradeSeverity::OutOfDate => match base {
            TcbStatus::UpToDate | TcbStatus::SWHardeningNeeded => TcbStatus::OutOfDate,
            TcbStatus::ConfigurationNeeded | TcbStatus::ConfigurationAndSWHardeningNeeded => {
                TcbStatus::OutOfDateConfigurationNeeded
            }
            other => other,
        },
    }
}

fn is_configuration_needed(status: TcbStatus) -> bool {
    matches!(
        status,
        TcbStatus::ConfigurationNeeded
            | TcbStatus::OutOfDateConfigurationNeeded
            | TcbStatus::ConfigurationAndSWHardeningNeeded
            | TcbStatus::TdRelaunchAdvisedConfigurationNeeded
    )
}

/// TDX 1.5 relaunch check: on a quote whose TD Report carries a second TEE TCB
/// SVN (`teeTcbSvn2`, from a service-TD-preserving relaunch), determine whether
/// the platform has since been updated enough that relaunching the TD against
/// the latest TDX Module/TCB Info would clear an `OutOfDate` status.
///
/// Ported from `TDRelaunchCheck.cpp`'s `checkForRelaunch`. Only applicable to
/// TD Report v1.5; callers must gate on quote/body version themselves.
fn check_for_relaunch(
    tee_tcb_svn2: &[u8; 16],
    tcb_info: &TcbInfo,
    sgx_tcb_status: TcbStatus,
    tdx_tcb_status: TcbStatus,
    tdx_module_tcb_status: TcbStatus,
    qe_tcb_outcome: Option<DowngradeSeverity>,
) -> Result<TcbStatus> {
    let qe_tcb_ruled_out = !matches!(
        qe_tcb_outcome,
        Some(DowngradeSeverity::OutOfDate) | Some(DowngradeSeverity::Revoked)
    );
    if !qe_tcb_ruled_out {
        return Ok(tdx_tcb_status);
    }

    let sgx_ok = matches!(
        sgx_tcb_status,
        TcbStatus::UpToDate
            | TcbStatus::SWHardeningNeeded
            | TcbStatus::ConfigurationNeeded
            | TcbStatus::ConfigurationAndSWHardeningNeeded
    );
    if !sgx_ok {
        return Ok(tdx_tcb_status);
    }

    let tdx_out_of_date = matches!(
        tdx_tcb_status,
        TcbStatus::OutOfDate | TcbStatus::OutOfDateConfigurationNeeded
    );
    if !tdx_out_of_date || tdx_module_tcb_status != TcbStatus::OutOfDate {
        return Ok(tdx_tcb_status);
    }

    let Some(latest_tcb_level) = tcb_info.tcb_levels.first() else {
        bail!("no TCB levels in TCB Info to check for TD relaunch");
    };

    let relaunch_clears_it = if tee_tcb_svn2[1] == 0 {
        let Some(latest_tdx_components) = &latest_tcb_level.tcb.tdxtcbcomponents else {
            bail!("latest TCB level is missing tdxtcbcomponents");
        };
        tee_tcb_svn2[0] >= latest_tdx_components[0].svn
            && tee_tcb_svn2[2] >= latest_tdx_components[2].svn
    } else {
        let module_id = format!("TDX_{:02X}", tee_tcb_svn2[1]);
        let Some(module) = tcb_info
            .tdx_module_identities
            .as_ref()
            .and_then(|ids| ids.iter().find(|i| i.id == module_id))
        else {
            bail!("no matching TDX Module Identity ({module_id}) for TD relaunch check");
        };
        let Some(latest_module_level) = module.tcb_levels.first() else {
            bail!("no TCB levels in matched TDX Module Identity for TD relaunch check");
        };
        let Some(latest_tdx_components) = &latest_tcb_level.tcb.tdxtcbcomponents else {
            bail!("latest TCB level is missing tdxtcbcomponents");
        };
        tee_tcb_svn2[0] >= latest_module_level.tcb.isvsvn.unwrap_or(u8::MAX)
            && tee_tcb_svn2[2] >= latest_tdx_components[2].svn
    };

    if !relaunch_clears_it {
        return Ok(tdx_tcb_status);
    }

    Ok(
        if is_configuration_needed(sgx_tcb_status) || is_configuration_needed(tdx_tcb_status) {
            TcbStatus::TdRelaunchAdvisedConfigurationNeeded
        } else {
            TcbStatus::TdRelaunchAdvised
        },
    )
}

/// `true` if `ref_tcb` is satisfied by the given SVNs — Intel's TCB Level
/// comparison logic (DCAP QVL step 3): all SGX TCB Comp SVNs and PCESVN from
/// the PCK certificate must be `>=` the reference level's, and, for TDX
/// quotes, the TD Report's TEE TCB SVNs must be too.
fn tcb_level_matches(
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
            .zip(r[idx..].iter())
            .all(|(td, reference)| td >= &reference.svn)
    })
}

/// Finds the first TCB Info level satisfied by the PCK certificate/quote TCB SVNs.
pub(crate) fn find_matching_tcb_level<'a>(
    tcb_levels: &'a [TcbLevel],
    pck_cpu_svns: &[u8],
    pck_cpu_pcesvn: u16,
    td_svns: Option<&[u8]>,
) -> Result<&'a TcbLevel> {
    tcb_levels
        .iter()
        .find(|lvl| tcb_level_matches(lvl, pck_cpu_svns, pck_cpu_pcesvn, td_svns))
        .context("no matching TCB Info level found for PCK certificate/quote TCB SVNs")
}

/// Finds the first level in a sorted TCB levels collection (QE Identity or
/// TDX Module Identity) whose `isvsvn` requirement `actual_isvsvn` satisfies.
pub(crate) fn find_tcb_level_by_isvsvn(levels: &[TcbLevel], actual_isvsvn: u16) -> Option<&TcbLevel> {
    levels
        .iter()
        .find(|level| level.tcb.isvsvn.unwrap_or(u8::MAX) as u16 <= actual_isvsvn)
}

/// Looks up the TDX Module Identity matching `tee_tcb_svn_version`
/// (`teeTcbSvn[1]`). A version of `0` means the module isn't tracked
/// separately from the platform-wide TCB baseline, so it isn't an error for
/// no identity to exist in that case.
pub(crate) fn find_tdx_module_identity(
    tcb_info: &TcbInfo,
    tee_tcb_svn_version: u8,
) -> Result<Option<&TdxModuleIdentity>> {
    if tee_tcb_svn_version == 0 {
        return Ok(None);
    }
    let module_id = format!("TDX_{tee_tcb_svn_version:02X}");
    tcb_info
        .tdx_module_identities
        .as_ref()
        .and_then(|identities| identities.iter().find(|i| i.id == module_id))
        .map(Some)
        .context("no matching TDX Module Identity found for quote's TEE TCB SVN")
}

/// The expected SEAM module `(mrsigner, attributes)`: the matched TDX Module
/// Identity's own fields once TEE TCB SVN[1] tracks the module separately,
/// otherwise the platform-wide `tcb_info.tdxModule` baseline.
///
/// Note: upstream QVL also fetches `attributesMask` here but never applies
/// it in the comparison callers make against the quote — matched verbatim,
/// mask included only for documentation of the field's presence in TCB Info.
pub(crate) fn expected_seam_identity<'a>(
    tcb_info: &'a TcbInfo,
    tdx_module_identity: Option<&'a TdxModuleIdentity>,
) -> Result<(&'a [u8], &'a HexBytes<8>)> {
    Ok(match tdx_module_identity {
        Some(identity) => (identity.mrsigner.as_slice(), &identity.attributes),
        None => {
            let tdx_module = tcb_info
                .tdx_module
                .as_ref()
                .context("TCB Info is missing tdxModule")?;
            (tdx_module.mrsigner.as_slice(), &tdx_module.attributes)
        }
    })
}

/// Converges the TCB Info level's status with the TDX Module Identity
/// level's status and the QE Identity level's status into the final
/// `tcb_status` claim, applying the TDX 1.5 relaunch check when
/// `tee_tcb_svn2` is present (TD Report v1.5 only).
pub(crate) fn converge(
    tcb_level_status: TcbStatus,
    tdx_module_level_status: Option<TcbStatus>,
    qe_tcb_level_status: TcbStatus,
    tee_tcb_svn2: Option<&[u8; 16]>,
    tcb_info: &TcbInfo,
) -> Result<TcbStatus> {
    let qe_tcb_severity = DowngradeSeverity::from_status(&qe_tcb_level_status);

    let mut tcb_status = match tdx_module_level_status {
        Some(module_status) => {
            downgrade(tcb_level_status, DowngradeSeverity::from_status(&module_status))
        }
        None => tcb_level_status,
    };

    if let Some(tee_tcb_svn2) = tee_tcb_svn2 {
        tcb_status = check_for_relaunch(
            tee_tcb_svn2,
            tcb_info,
            tcb_level_status,
            tcb_status,
            tdx_module_level_status.unwrap_or(TcbStatus::UpToDate),
            Some(qe_tcb_severity),
        )?;
    }

    Ok(downgrade(tcb_status, qe_tcb_severity))
}

/// Merges advisory IDs from the converged TCB Info, QE Identity, and (if
/// present) TDX Module Identity TCB levels into one deduplicated, sorted set.
pub(crate) fn merge_advisory_ids(
    tcb_level: &TcbLevel,
    qe_tcb_level: &TcbLevel,
    tdx_module_tcb_level: Option<&TcbLevel>,
) -> BTreeSet<String> {
    tcb_level
        .advisory_ids
        .iter()
        .flatten()
        .chain(qe_tcb_level.advisory_ids.iter().flatten())
        .chain(
            tdx_module_tcb_level
                .into_iter()
                .flat_map(|l| l.advisory_ids.iter().flatten()),
        )
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use TcbStatus::*;

    #[rstest]
    // UpToDate severity: pass through unchanged, regardless of base.
    #[case(UpToDate, DowngradeSeverity::UpToDate, UpToDate)]
    #[case(OutOfDate, DowngradeSeverity::UpToDate, OutOfDate)]
    // OutOfDate severity: UpToDate/SWHardeningNeeded base -> OutOfDate.
    #[case(UpToDate, DowngradeSeverity::OutOfDate, OutOfDate)]
    #[case(SWHardeningNeeded, DowngradeSeverity::OutOfDate, OutOfDate)]
    // OutOfDate severity: ConfigurationNeeded/ConfigurationAndSWHardeningNeeded base -> OutOfDateConfigurationNeeded.
    #[case(
        ConfigurationNeeded,
        DowngradeSeverity::OutOfDate,
        OutOfDateConfigurationNeeded
    )]
    #[case(
        ConfigurationAndSWHardeningNeeded,
        DowngradeSeverity::OutOfDate,
        OutOfDateConfigurationNeeded
    )]
    // OutOfDate severity: already-worse base statuses pass through unchanged.
    #[case(OutOfDate, DowngradeSeverity::OutOfDate, OutOfDate)]
    #[case(Revoked, DowngradeSeverity::OutOfDate, Revoked)]
    #[case(
        OutOfDateConfigurationNeeded,
        DowngradeSeverity::OutOfDate,
        OutOfDateConfigurationNeeded
    )]
    // Revoked severity always wins, regardless of base.
    #[case(UpToDate, DowngradeSeverity::Revoked, Revoked)]
    #[case(OutOfDate, DowngradeSeverity::Revoked, Revoked)]
    fn test_downgrade(
        #[case] base: TcbStatus,
        #[case] severity: DowngradeSeverity,
        #[case] expected: TcbStatus,
    ) {
        let result = downgrade(base, severity);
        assert_eq!(format!("{result}"), format!("{expected}"));
    }

    /// Builds a minimal `TcbInfo` with one TCB level (`tdxtcbcomponents` all-zero except
    /// index 0/2 set from `latest_svn`) and, if `module_id` is given, one TDX Module
    /// Identity with that id and one TCB level with the given `isvsvn`.
    fn make_tcb_info(latest_svn: (u8, u8), module: Option<(&str, u8)>) -> TcbInfo {
        let (svn0, svn2) = latest_svn;
        let module_json = module
            .map(|(id, isvsvn)| {
                format!(
                    r#","tdxModuleIdentities":[{{"id":"{id}","mrsigner":"{}","attributes":"0000000000000000","attributesMask":"0000000000000000","tcbLevels":[{{"tcb":{{"isvsvn":{isvsvn}}},"tcbDate":"2024-01-01T00:00:00Z","tcbStatus":"UpToDate"}}]}}]"#,
                    "00".repeat(48)
                )
            })
            .unwrap_or_default();
        let json = format!(
            r#"{{
                "id":"TDX","version":3,"issueDate":"2024-01-01T00:00:00Z","nextUpdate":"2024-02-01T00:00:00Z",
                "fmspc":"000000000000","pceId":"0000","tcbType":0,"tcbEvaluationDataNumber":1
                {module_json},
                "tcbLevels":[{{"tcb":{{"tdxtcbcomponents":[
                    {{"svn":{svn0}}},{{"svn":0}},{{"svn":{svn2}}},{{"svn":0}},{{"svn":0}},{{"svn":0}},
                    {{"svn":0}},{{"svn":0}},{{"svn":0}},{{"svn":0}},{{"svn":0}},{{"svn":0}},
                    {{"svn":0}},{{"svn":0}},{{"svn":0}},{{"svn":0}}
                ]}},"tcbDate":"2024-01-01T00:00:00Z","tcbStatus":"OutOfDate"}}]
            }}"#
        );
        serde_json::from_str(&json).expect("valid TcbInfo test fixture")
    }

    fn tee_tcb_svn2(svn0: u8, svn1: u8, svn2: u8) -> [u8; 16] {
        let mut svn = [0u8; 16];
        svn[0] = svn0;
        svn[1] = svn1;
        svn[2] = svn2;
        svn
    }

    #[test]
    fn relaunch_not_applicable_when_qe_tcb_out_of_date() {
        let tcb_info = make_tcb_info((5, 5), None);
        let result = check_for_relaunch(
            &tee_tcb_svn2(5, 0, 5),
            &tcb_info,
            UpToDate,
            OutOfDate,
            OutOfDate,
            Some(DowngradeSeverity::OutOfDate),
        )
        .unwrap();
        assert_eq!(format!("{result}"), format!("{OutOfDate}"));
    }

    #[test]
    fn relaunch_advised_when_svn2_clears_latest_level_module_version_zero() {
        let tcb_info = make_tcb_info((5, 5), None);
        let result = check_for_relaunch(
            &tee_tcb_svn2(5, 0, 5),
            &tcb_info,
            UpToDate,
            OutOfDate,
            OutOfDate,
            None,
        )
        .unwrap();
        assert_eq!(format!("{result}"), format!("{TdRelaunchAdvised}"));
    }

    #[test]
    fn relaunch_advised_with_configuration_needed_when_sgx_status_requires_it() {
        let tcb_info = make_tcb_info((5, 5), None);
        let result = check_for_relaunch(
            &tee_tcb_svn2(5, 0, 5),
            &tcb_info,
            ConfigurationNeeded,
            OutOfDate,
            OutOfDate,
            None,
        )
        .unwrap();
        assert_eq!(
            format!("{result}"),
            format!("{TdRelaunchAdvisedConfigurationNeeded}")
        );
    }

    #[test]
    fn relaunch_not_advised_when_svn2_does_not_clear_latest_level() {
        let tcb_info = make_tcb_info((5, 5), None);
        // svn2[0] = 4 < latest level's tdxtcbcomponents[0].svn = 5.
        let result = check_for_relaunch(
            &tee_tcb_svn2(4, 0, 5),
            &tcb_info,
            UpToDate,
            OutOfDate,
            OutOfDate,
            None,
        )
        .unwrap();
        assert_eq!(format!("{result}"), format!("{OutOfDate}"));
    }

    #[test]
    fn relaunch_advised_via_matched_tdx_module_identity_when_svn2_1_nonzero() {
        let tcb_info = make_tcb_info((0, 5), Some(("TDX_02", 3)));
        let result = check_for_relaunch(
            &tee_tcb_svn2(3, 2, 5),
            &tcb_info,
            UpToDate,
            OutOfDate,
            OutOfDate,
            None,
        )
        .unwrap();
        assert_eq!(format!("{result}"), format!("{TdRelaunchAdvised}"));
    }

    #[test]
    fn relaunch_check_errors_when_matched_module_identity_missing() {
        let tcb_info = make_tcb_info((0, 5), None);
        let result = check_for_relaunch(
            &tee_tcb_svn2(3, 2, 5),
            &tcb_info,
            UpToDate,
            OutOfDate,
            OutOfDate,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn relaunch_not_applicable_when_tdx_module_status_not_out_of_date() {
        let tcb_info = make_tcb_info((5, 5), None);
        let result = check_for_relaunch(
            &tee_tcb_svn2(5, 0, 5),
            &tcb_info,
            UpToDate,
            OutOfDate,
            UpToDate,
            None,
        )
        .unwrap();
        assert_eq!(format!("{result}"), format!("{OutOfDate}"));
    }

    use crate::intel_dcap::collateral_service::{Tcb, TcbComponent, TcbComponentList};

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
            tcb_date: chrono::Utc::now(),
            tcb_status: TcbStatus::UpToDate,
            advisory_ids: None,
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
    fn test_tcb_level_matches(
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
            tcb_level_matches(
                &lvl,
                &cert_svns,
                cert_pcesvn,
                td_svns.as_ref().map(|s| s.as_slice())
            ),
            expected,
            "case: {_desc}"
        );
    }
}
