// Copyright (c) 2026 Confidential Containers Project Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Crypto primitives used by DCAP quote/collateral verification: SHA-256/384
//! hashing and ECDSA-P256-SHA256 signature verification over a fixed
//! uncompressed public key point (`x || y`, 32 bytes each) and a fixed
//! `r || s` signature encoding (32 bytes each) — the shapes DCAP quotes and
//! PCS collateral use throughout.
//!
//! Backed by `ring`, the same crypto engine `x509-parser`'s own `verify`
//! feature delegates to for certificate/CRL signature checks (see `cert.rs`),
//! so the whole module has a single crypto implementation underneath it.
//!
//! `ecdsa_p256_verify` takes the raw signed `message`, not a pre-computed
//! digest: `ring`'s `VerificationAlgorithm::verify` hashes the message
//! internally as part of verification and has no public API to verify
//! against an already-computed digest.

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    digest
        .as_ref()
        .try_into()
        .expect("SHA-256 digest is 32 bytes")
}

pub(crate) fn sha384(data: &[u8]) -> [u8; 48] {
    let digest = ring::digest::digest(&ring::digest::SHA384, data);
    digest
        .as_ref()
        .try_into()
        .expect("SHA-384 digest is 48 bytes")
}

/// Verifies an ECDSA-P256-SHA256 signature over the raw `message` against
/// the public key given as raw affine coordinates.
pub(crate) fn ecdsa_p256_verify(
    message: &[u8],
    sig_r: &[u8; 32],
    sig_s: &[u8; 32],
    pub_key_x: &[u8; 32],
    pub_key_y: &[u8; 32],
) -> anyhow::Result<bool> {
    // ring's fixed-length (PKCS#11-style) ECDSA verification takes the
    // uncompressed SEC1 point (0x04 || X || Y) and a raw r||s signature —
    // exactly the shapes DCAP quotes/collateral already use. It hashes
    // `message` internally, so this must receive the raw signed bytes,
    // not a pre-computed digest.
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(pub_key_x);
    point[33..65].copy_from_slice(pub_key_y);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(sig_r);
    sig[32..].copy_from_slice(sig_s);

    let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, point);

    // ring collapses "malformed input" and "signature does not match" into
    // the same opaque error, so a verification failure is a `false` result,
    // not an `Err`.
    match key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty_and_abc_match_known_vectors() {
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha384_empty_and_abc_match_known_vectors() {
        assert_eq!(
            hex::encode(sha384(b"")),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            hex::encode(sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    /// Generates a fresh P-256 keypair via OpenSSL (a test-vector generator
    /// only — production code above never touches OpenSSL), signs
    /// SHA-256(`message`), and returns the affine public key coordinates and
    /// signature as the fixed-size arrays `ecdsa_p256_verify` takes.
    fn sign(message: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        use openssl::bn::{BigNum, BigNumContext};
        use openssl::ec::{EcGroup, EcKey};
        use openssl::ecdsa::EcdsaSig;
        use openssl::nid::Nid;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();

        let mut ctx = BigNumContext::new().unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        key.public_key()
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
            .unwrap();

        let hash = openssl::sha::sha256(message);
        let sig = EcdsaSig::sign(&hash, &key).unwrap();

        let to_array = |bn: &openssl::bn::BigNumRef| -> [u8; 32] {
            bn.to_vec_padded(32).unwrap().try_into().unwrap()
        };

        (
            to_array(&x),
            to_array(&y),
            to_array(sig.r()),
            to_array(sig.s()),
        )
    }

    #[test]
    fn ecdsa_p256_verify_accepts_openssl_signed_signature() {
        // Cross-implementation interop: sign with OpenSSL, verify with ring.
        let (x, y, r, s) = sign(b"hello world");
        assert!(ecdsa_p256_verify(b"hello world", &r, &s, &x, &y).unwrap());
    }

    #[test]
    fn ecdsa_p256_verify_rejects_tampered_message() {
        let (x, y, r, s) = sign(b"hello world");
        assert!(!ecdsa_p256_verify(b"goodbye world", &r, &s, &x, &y).unwrap());
    }

    #[test]
    fn ecdsa_p256_verify_rejects_wrong_key() {
        let (_, _, r, s) = sign(b"hello world");
        let (other_x, other_y, _, _) = sign(b"hello world");
        assert!(!ecdsa_p256_verify(b"hello world", &r, &s, &other_x, &other_y).unwrap());
    }
}
