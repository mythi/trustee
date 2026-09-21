// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Vendor/profile-specific CoRIM extraction.
//!
//! A CoRIM can declare a `profile` identifier (a URI or OID) that governs
//! how its extension points -- such as vendor-private mval keys -- should
//! be interpreted. The base reference-triple extractor in the parent
//! module doesn't need this: it only reads spec-defined mval fields, so it
//! runs unconditionally regardless of profile. Anything that interprets
//! vendor-private extension points, like Intel's POE profile, belongs
//! here instead, gated on the CoRIM's own declared profile identifier --
//! so a differently-vendored CoRIM that happens to have a structurally
//! similar triple is never misinterpreted as some other vendor's profile.
//!
//! Dispatch below is a static, trusted lookup table keyed by the declared
//! profile identifier -- not a mechanism for the CoRIM itself to select or
//! load its own parsing logic. Trusting an artifact to pick its own
//! interpreter would be the CBOR equivalent of unsafe deserialization;
//! the profile field only ever selects among extractors RVPS already
//! ships and trusts.

use anyhow::Result;
use corim_rs::ConciseMidTag;

use crate::ReferenceValue;

/// Extracts reference values from a CoMID whose containing CoRIM declared
/// support for one of `profiles()`.
pub(super) trait CorimProfileExtractor: Send + Sync {
    /// Profile identifiers (as they appear in a CoRIM's `profile` field)
    /// this extractor knows how to handle.
    fn profiles(&self) -> &[&str];

    fn extract(&self, comid: &ConciseMidTag) -> Result<Vec<ReferenceValue>>;
}

/// The trusted set of known profile extractors. Adding support for a new
/// vendor profile means adding a module here and one entry to this list --
/// no changes to the shared CoRIM dispatch logic in the parent module.
fn registered_extractors() -> Vec<Box<dyn CorimProfileExtractor>> {
    vec![]
}

/// Runs every registered extractor that declares support for `profile_id`
/// against `comid`, and returns the combined reference values.
pub(super) fn extract_for_profile(
    profile_id: &str,
    comid: &ConciseMidTag,
) -> Result<Vec<ReferenceValue>> {
    let mut rvs = vec![];
    for extractor in registered_extractors() {
        if extractor.profiles().contains(&profile_id) {
            rvs.extend(extractor.extract(comid)?);
        }
    }
    Ok(rvs)
}
