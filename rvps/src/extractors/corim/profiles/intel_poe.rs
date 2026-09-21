// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Intel Platform Ownership Endorsement (POE) profile
//! (`tag:intel.com,2026:tee.poe#1.0`, produced by `poe-gen-tool`).
//!
//! POE CoRIMs bind a Platform Instance ID (PIID) to an owner name via a
//! conditional-endorsement triple, not a reference-triple: a signed
//! statement of the form "if the platform's PIID is X, its owner is Y".
//! Both mval fields are POE profile-private extension keys, so they land
//! in `MeasurementValuesMap::extensions` rather than any of corim_rs's
//! named mval fields.
//!
//! ## Input: the to-be-signed CBOR, not the signed CoRIM
//!
//! This extractor never verifies CoRIM signatures (see the parent
//! module), so there is no benefit to requiring a fully signed POE
//! artifact. Instead it accepts the same to-be-signed bytes a caller
//! would otherwise send to a signer -- `poe-gen-tool derive-tbs`/
//! `prepare`'s `poe.tbs.cbor` output, a raw COSE `Sig_Structure`
//! (RFC 9052 SS4.4: `["Signature1", protected, external_aad, payload]`).
//! `unwrap_sig_structure_payload` (in the parent module) pulls the
//! unsigned CoRIM (tag 501) out of that, so a caller never has to
//! complete signing at all to register a POE endorsement here. A fully
//! signed artifact (COSE_Sign1, tag 18) works too, for any *other*
//! spec-conformant profile -- `corim_rs`'s own `SignedCorim` already
//! handles that path natively.
//!
//! ## Known CDDL deviation from the base CoRIM spec
//!
//! POE's own schema describes itself as "a narrowing of
//! draft-ietf-rats-corim-10," but its profile identifier's encoding is a
//! deviation, not a narrowing: the base spec's `$profile-type-choice`
//! socket only has two plugs, `uri` (`#6.32(tstr)`) and `tagged-oid-type`
//! (`#6.111(bytes)`) -- both CBOR-tagged. POE's CDDL types its own
//! profile identifier as a bare `tstr`, with no tag, so real POE CoRIMs
//! don't parse as that socket against a strictly spec-conformant
//! implementation. `corim_rs` is not at fault here; it correctly
//! implements the base spec. Worked around in the parent module's
//! `profile_identifier`, in the
//! `ProfileTypeChoice::Extension(ExtensionValue::Text(_))` arm.

use anyhow::Result;
use corim_rs::{ClassIdTypeChoice, ConciseMidTag, ExtensionValue, Integer};
use tracing::debug;

use crate::ReferenceValue;

use super::CorimProfileExtractor;

const PROFILE_ID: &str = "tag:intel.com,2026:tee.poe#1.0";
const PIID_ENV_OID: &str = "2.16.840.1.113741.1.13.2.6.1";
const OWNER_ENDORSE_OID: &str = "2.16.840.1.113741.1.13.2.12.1";
const PIID_MVAL_KEY: i128 = -101;
const OWNER_NAME_MVAL_KEY: i128 = -401;

pub(super) struct IntelPoeExtractor;

impl CorimProfileExtractor for IntelPoeExtractor {
    fn profiles(&self) -> &[&str] {
        &[PROFILE_ID]
    }

    /// The resulting RV is named `intel_poe/owner_name/<piid-hex>` so a
    /// policy can look up the expected owner for a platform by the PIID
    /// reported in that platform's own evidence.
    fn extract(&self, comid: &ConciseMidTag) -> Result<Vec<ReferenceValue>> {
        let mut rvs = vec![];

        let Some(cond_endorse_triples) = &comid.triples.conditional_endorsement_triples else {
            return Ok(rvs);
        };

        for triple in cond_endorse_triples {
            let piid_hex = triple.conditions.iter().find_map(|cond| {
                let class = cond.environment.class.as_ref()?;
                let ClassIdTypeChoice::Oid(oid) = class.class_id.as_ref()? else {
                    return None;
                };
                if oid.to_string() != PIID_ENV_OID {
                    return None;
                }

                cond.claims_list.iter().find_map(|claim| {
                    match claim
                        .mval
                        .extensions
                        .as_ref()
                        .and_then(|ext| ext.0.get(&Integer(PIID_MVAL_KEY)))
                    {
                        Some(ExtensionValue::Bytes(b)) => Some(hex::encode(b.as_slice())),
                        _ => None,
                    }
                })
            });

            let Some(piid_hex) = piid_hex else {
                debug!(
                    "Skipping POE conditional-endorsement triple with no recognized PIID condition"
                );
                continue;
            };

            let owner_name = triple.endorsements.iter().find_map(|endorse| {
                let class = endorse.condition.class.as_ref()?;
                let ClassIdTypeChoice::Oid(oid) = class.class_id.as_ref()? else {
                    return None;
                };
                if oid.to_string() != OWNER_ENDORSE_OID {
                    return None;
                }

                endorse.endorsement.iter().find_map(|meas| {
                    match meas
                        .mval
                        .extensions
                        .as_ref()
                        .and_then(|ext| ext.0.get(&Integer(OWNER_NAME_MVAL_KEY)))
                    {
                        Some(ExtensionValue::Text(t)) => Some(t.to_string()),
                        _ => None,
                    }
                })
            });

            let Some(owner_name) = owner_name else {
                debug!(
                    "Skipping POE conditional-endorsement triple with no recognized owner-name endorsement"
                );
                continue;
            };

            let name = format!("intel_poe/owner_name/{piid_hex}");
            let rv = ReferenceValue::new()?
                .set_name(&name)
                .set_value(serde_json::Value::String(owner_name));

            rvs.push(rv);
        }

        Ok(rvs)
    }
}
