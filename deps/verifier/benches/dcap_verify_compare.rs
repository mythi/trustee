// Copyright (c) 2026 Confidential Containers Project Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Criterion benchmark comparing the C-FFI DCAP QVL verification path
//! (`ecdsa_quote_verification`, backed by `intel-tee-quote-verification-rs`)
//! against the pure-Rust reimplementation (`intel_dcap::verify::dcap_verify`).
//!
//! Collateral is fetched once before each group's timed loop, then reused
//! across iterations, so what's measured is verification cost (crypto +
//! certificate chain validation), not network/HTTP overhead.
//!
//! Requires network access to `api.trustedservices.intel.com`.
//!
//! Run with:
//!   cargo bench -p verifier --features bench --bench dcap_verify_compare

use chrono::Utc;
use criterion::{criterion_group, criterion_main, Criterion};
use verifier::bench_support::{
    build_quote_collateral, dcap_verify, ecdsa_quote_verification, quote_collateral_params,
    QcnlConfig,
};

const QUOTE_FILE: &str = "test_data/tdx_quote_4.dat";

fn bench_c_ffi_verify_only(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let quote_bytes = std::fs::read(QUOTE_FILE).expect("read tdx_quote_4.dat");
    let (fmspc, is_platform_ca, tee_type) =
        quote_collateral_params(&quote_bytes).expect("parse quote collateral params");

    let pcs = QcnlConfig::default().pcs().expect("construct Pcs");
    let collateral = rt
        .block_on(build_quote_collateral(
            fmspc,
            is_platform_ca,
            tee_type,
            &pcs,
        ))
        .expect("fetch collateral from PCS");

    c.bench_function("c_ffi_verify_only", |b| {
        b.iter(|| {
            ecdsa_quote_verification(&quote_bytes, Some(collateral.clone()))
                .expect("ecdsa_quote_verification failed")
        })
    });
}

fn bench_rust_verify_only(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let quote_bytes = std::fs::read(QUOTE_FILE).expect("read tdx_quote_4.dat");
    let pcs = QcnlConfig::default().pcs().expect("construct Pcs");
    let now = Utc::now();

    // Warm up http-cache-reqwest's in-memory cache so the timed loop's PCS
    // calls are served from cache rather than the network. dcap_verify takes
    // a `&impl CollateralService`, not pre-built collateral, so each
    // iteration still calls through Pcs::get() — but the cache keeps that
    // off the network after this warm-up call.
    rt.block_on(dcap_verify(&quote_bytes, &now, &pcs))
        .expect("warm-up dcap_verify failed");

    c.bench_function("rust_verify_only", |b| {
        b.iter(|| {
            rt.block_on(dcap_verify(&quote_bytes, &now, &pcs))
                .expect("dcap_verify failed")
        })
    });
}

criterion_group!(benches, bench_c_ffi_verify_only, bench_rust_verify_only);
criterion_main!(benches);
