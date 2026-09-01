//! Runtime tests against the crate compiled without the `std` feature.
//!
//! Run with:
//! `cargo test --no-default-features --features pure_rust --test no_std`

#![cfg(not(feature = "std"))]

extern crate alloc;

use alloc::string::String;

use rand::rngs::StdRng;
use rand::SeedableRng;

fn seeded_rng() -> StdRng {
    StdRng::from_seed([0xA5; 32])
}

const _: () = assert!(!cfg!(feature = "std"));

#[test]
fn generate_encrypt_decrypt_roundtrip() {
    let mut rng = seeded_rng();
    let (secret, public) = ecies_ed25519::generate_keypair(&mut rng);

    let message = b"no_std ECIES roundtrip";
    let encrypted = ecies_ed25519::encrypt(&public, message, &mut rng).unwrap();
    let decrypted = ecies_ed25519::decrypt(&secret, &encrypted).unwrap();

    assert_eq!(decrypted.as_slice(), message);
}

#[test]
fn secret_key_from_bytes_and_hex() {
    use hex::{FromHex, ToHex};

    let mut rng = seeded_rng();
    let (secret, public) = ecies_ed25519::generate_keypair(&mut rng);

    let secret_again =
        ecies_ed25519::SecretKey::from_bytes(secret.as_bytes()).expect("secret bytes");
    let public_again =
        ecies_ed25519::PublicKey::from_bytes(public.as_bytes()).expect("public bytes");

    assert_eq!(secret.as_bytes(), secret_again.as_bytes());
    assert_eq!(public.as_bytes(), public_again.as_bytes());

    let secret_hex: String = secret.encode_hex();
    let public_hex: String = public.encode_hex();

    let secret_from_hex = ecies_ed25519::SecretKey::from_hex(&secret_hex).unwrap();
    let public_from_hex = ecies_ed25519::PublicKey::from_hex(&public_hex).unwrap();

    assert_eq!(secret.as_bytes(), secret_from_hex.as_bytes());
    assert_eq!(public.as_bytes(), public_from_hex.as_bytes());
}

#[test]
fn decrypt_rejects_short_ciphertext() {
    let mut rng = seeded_rng();
    let (secret, _) = ecies_ed25519::generate_keypair(&mut rng);

    let err = ecies_ed25519::decrypt(&secret, &[0u8; 16]).unwrap_err();
    assert!(matches!(
        err,
        ecies_ed25519::Error::DecryptionFailedCiphertextShort
    ));
}

#[cfg(feature = "serde")]
#[test]
fn serde_json_roundtrip_without_std_on_crate() {
    let mut rng = seeded_rng();
    let (secret, public) = ecies_ed25519::generate_keypair(&mut rng);

    let secret_json = serde_json::to_string(&secret).unwrap();
    let public_json = serde_json::to_string(&public).unwrap();

    let secret_de: ecies_ed25519::SecretKey = serde_json::from_str(&secret_json).unwrap();
    let public_de: ecies_ed25519::PublicKey = serde_json::from_str(&public_json).unwrap();

    assert_eq!(secret.as_bytes(), secret_de.as_bytes());
    assert_eq!(public.as_bytes(), public_de.as_bytes());
}
