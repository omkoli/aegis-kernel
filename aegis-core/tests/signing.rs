use aegis_core::{
    Action, AegisError, CapabilityToken, Constraints, Ed25519TokenSigner, Ed25519TokenVerifier,
    ParamConstraint, Resource, TokenSigner,
};
use std::time::Instant;

fn make_token() -> CapabilityToken {
    let resource = Resource::new("file:///etc/passwd").unwrap();
    CapabilityToken::new(
        "test-user",
        resource,
        vec![Action::Read],
        Constraints::new(),
        None,
        false,
        None,
    )
    .unwrap()
}

fn make_complex_token() -> CapabilityToken {
    let resource = Resource::new("net://db.internal/users").unwrap();
    let constraints = Constraints::new()
        .add(
            "max_rows",
            ParamConstraint::Range {
                min: 1.0,
                max: 1000.0,
            },
        )
        .unwrap()
        .add("format", ParamConstraint::Exact("json".into()))
        .unwrap();
    CapabilityToken::new(
        "test-user",
        resource,
        vec![
            Action::Read,
            Action::Write,
            Action::custom("query").unwrap(),
        ],
        constraints,
        None,
        true,
        Some(10),
    )
    .unwrap()
}

// ── Sign & Verify ───────────────────────────────────────────────────────

#[test]
fn sign_and_verify_simple_token() {
    let signer = Ed25519TokenSigner::generate();
    let token = make_token();
    let sig = signer.sign(&token).unwrap();
    assert!(signer.verify(&token, &sig).is_ok());
}

#[test]
fn sign_and_verify_complex_token() {
    let signer = Ed25519TokenSigner::generate();
    let token = make_complex_token();
    let sig = signer.sign(&token).unwrap();
    assert!(signer.verify(&token, &sig).is_ok());
}

// ── Tamper Detection ────────────────────────────────────────────────────

#[test]
fn tamper_detection_different_token() {
    let signer = Ed25519TokenSigner::generate();
    let token1 = make_token();
    let token2 = make_complex_token();
    let sig = signer.sign(&token1).unwrap();
    let err = signer.verify(&token2, &sig).unwrap_err();
    assert!(matches!(err, AegisError::SignatureInvalid(_)));
}

#[test]
fn tamper_detection_mutated_signature_bytes() {
    let signer = Ed25519TokenSigner::generate();
    let token = make_token();
    let sig = signer.sign(&token).unwrap();
    let mut bytes = sig.to_bytes();
    bytes[0] ^= 0xff;
    let tampered = aegis_core::TokenSignature::from_bytes(&bytes);
    let err = signer.verify(&token, &tampered).unwrap_err();
    assert!(matches!(err, AegisError::SignatureInvalid(_)));
}

// ── Wrong Key Rejection ─────────────────────────────────────────────────

#[test]
fn wrong_key_rejected() {
    let signer1 = Ed25519TokenSigner::generate();
    let signer2 = Ed25519TokenSigner::generate();
    let token = make_token();
    let sig = signer1.sign(&token).unwrap();
    let err = signer2.verify(&token, &sig).unwrap_err();
    assert!(matches!(err, AegisError::SignatureInvalid(_)));
}

#[test]
fn wrong_key_rejected_via_verifier() {
    let signer = Ed25519TokenSigner::generate();
    let other = Ed25519TokenSigner::generate();
    let verifier = Ed25519TokenVerifier::new(other.verifying_key());
    let token = make_token();
    let sig = signer.sign(&token).unwrap();
    let err = verifier.verify(&token, &sig).unwrap_err();
    assert!(matches!(err, AegisError::SignatureInvalid(_)));
}

// ── Verifier-only path ──────────────────────────────────────────────────

#[test]
fn verifier_accepts_valid_signature() {
    let signer = Ed25519TokenSigner::generate();
    let verifier = Ed25519TokenVerifier::new(signer.verifying_key());
    let token = make_token();
    let sig = signer.sign(&token).unwrap();
    assert!(verifier.verify(&token, &sig).is_ok());
}

// ── Signature is 64 bytes ───────────────────────────────────────────────

#[test]
fn signature_is_64_bytes() {
    let signer = Ed25519TokenSigner::generate();
    let token = make_token();
    let sig = signer.sign(&token).unwrap();
    assert_eq!(sig.to_bytes().len(), 64);
}

// ── Deterministic: same key + same token = same signature ───────────────

#[test]
fn signing_is_deterministic() {
    let signer = Ed25519TokenSigner::generate();
    let token = make_token();
    let sig1 = signer.sign(&token).unwrap();
    let sig2 = signer.sign(&token).unwrap();
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
}

// ── Serde roundtrip for TokenSignature ──────────────────────────────────

#[test]
fn signature_serde_roundtrip() {
    let signer = Ed25519TokenSigner::generate();
    let token = make_token();
    let sig = signer.sign(&token).unwrap();
    let json = serde_json::to_string(&sig).unwrap();
    let sig2: aegis_core::TokenSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), sig2.to_bytes());
    // Verify the deserialized signature still works
    assert!(signer.verify(&token, &sig2).is_ok());
}

#[test]
fn signature_hex_encoding_is_128_chars() {
    let signer = Ed25519TokenSigner::generate();
    let token = make_token();
    let sig = signer.sign(&token).unwrap();
    let json = serde_json::to_string(&sig).unwrap();
    // JSON string includes quotes, so 128 + 2
    assert_eq!(json.len(), 130);
}

// ── Canonical JSON tests ────────────────────────────────────────────────

#[test]
fn canonical_json_produces_same_bytes_for_same_token() {
    let token = make_token();
    let b1 = aegis_core::canonical_json(&token).unwrap();
    let b2 = aegis_core::canonical_json(&token).unwrap();
    assert_eq!(b1, b2);
}

// ── Performance: sign + verify benchmark ────────────────────────────────
// Ed25519 achieves <100µs in release mode. In debug/test profile the
// unoptimised curve arithmetic is ~100x slower, so we use a relaxed
// threshold here and rely on `cargo bench` (release) for the real gate.

#[test]
fn sign_verify_performance() {
    let signer = Ed25519TokenSigner::generate();
    let token = make_token();

    // Warm up
    let sig = signer.sign(&token).unwrap();
    signer.verify(&token, &sig).unwrap();

    let iterations = 100;
    let start = Instant::now();
    for _ in 0..iterations {
        let sig = signer.sign(&token).unwrap();
        signer.verify(&token, &sig).unwrap();
    }
    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

    eprintln!(
        "sign+verify avg: {avg_micros:.1}µs over {iterations} iterations ({:.0} ops/sec)",
        1_000_000.0 / avg_micros
    );

    // Debug builds: allow up to 50ms. Release target is <100µs.
    assert!(
        avg_micros < 50_000.0,
        "sign+verify took {avg_micros:.1}µs on average, unexpectedly slow even for debug"
    );
}
