//! ECIES-ed25519: An Integrated Encryption Scheme on Twisted Edwards Curve25519.
//!
//! It uses many of the same primitives as the ed25519 signature scheme, but is also different.
//!   - It uses the same Secret Key representation as the ed25519 signature scheme.
//!   - It uses a different Public Key representation. While the ed25519 signature scheme hashes the
//!     secret key and mangles some bits before using it to derive the public key,
//!     ECIES-ed25519 uses the secret key directly. This means you should take care to
//!     use a good secure RNG or KDF to generate a your secret key.

use curve25519_dalek::constants;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::PublicKey as EdPublicKey;
pub use ed25519_dalek::SecretKey;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use failure::Fail;
use rand::{CryptoRng, RngCore};

#[cfg(feature = "ring")]
mod ring_backend;

#[cfg(feature = "ring")]
use ring_backend::*;

#[cfg(feature = "pure_rust")]
mod pure_rust_backend;

#[cfg(feature = "pure_rust")]
use pure_rust_backend::*;

#[cfg(not(any(feature = "ring", feature = "pure_rust")))]
compile_error!("Either feature 'ring' or 'pure_rust' must be enabled for this crate.");

#[cfg(all(feature = "ring", feature = "pure_rust"))]
compile_error!("Feature 'ring' and 'pure_rust' cannot both be enabled. Please choose one.");

const HKDF_INFO: &[u8; 13] = b"ecies-ed25519";
const HKDF_SALT: &[u8; 16] = &[
    5, 86, 190, 123, 235, 189, 45, 218, 78, 3, 87, 193, 152, 95, 224, 1,
];

const AES_IV_LENGTH: usize = 12;

type AesKey = [u8; 32];
type SharedSecret = [u8; 32];

/// An ed25519 Public Key meant for use in ECIES.
///
/// Neither this public key (nor it's corresponding  PrivateKey) should be used for signing
/// or in any other protocol other than ECIES.
#[derive(Debug, Clone)]
pub struct PublicKey(EdPublicKey);

impl PublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// Will return None if the bytes are invalid
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let public = EdPublicKey::from_bytes(bytes).map_err(|_| Error::InvalidPublicKeyBytes)?;

        Ok(PublicKey(public))
    }

    /// Derive a public key from a private key
    pub fn from_secret(sk: &SecretKey) -> Self {
        let point = &Scalar::from_bits(sk.to_bytes()) * &constants::ED25519_BASEPOINT_TABLE;
        let public = EdPublicKey::from_bytes(&point.compress().to_bytes())
            .expect("ecies-ed25519: unexpect error generating public key from private key");
        PublicKey(public)
    }

    /// Get the Edwards Point for this public key
    pub fn as_point(&self) -> EdwardsPoint {
        CompressedEdwardsY::from_slice(self.0.as_bytes())
            .decompress()
            .expect("ecies-ed25519: unexpect error decompressing public key")
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Generate a keypair, ready for use in ECIES
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SecretKey, PublicKey) {
    let ed25519_dalek::Keypair { public: _, secret } = ed25519_dalek::Keypair::generate(rng);
    let public = PublicKey::from_secret(&secret);
    (secret, public)
}

/// Encrypt a message using ECIES, it can only be decrypted by the receiver's SecretKey.
pub fn encrypt<R: CryptoRng + RngCore>(
    receiver_pub: &PublicKey,
    msg: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let (ephemeral_sk, ephemeral_pk) = generate_keypair(rng);

    let aes_key = encapsulate(&ephemeral_sk, &receiver_pub);
    let encrypted = aes_encrypt(&aes_key, msg, rng)?;

    let mut cipher_text = Vec::with_capacity(PUBLIC_KEY_LENGTH + encrypted.len());
    cipher_text.extend(ephemeral_pk.to_bytes().iter());
    cipher_text.extend(encrypted);

    Ok(cipher_text)
}

/// Decrypt a ECIES encrypted ciphertext using the receiver's SecretKey.
pub fn decrypt(receiver_sec: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.len() <= PUBLIC_KEY_LENGTH {
        return Err(Error::DecryptionFailedCiphertextShort);
    }

    let ephemeral_pk = PublicKey::from_bytes(&ciphertext[..PUBLIC_KEY_LENGTH])?;
    let encrypted = &ciphertext[PUBLIC_KEY_LENGTH..];
    let aes_key = decapsulate(&receiver_sec, &ephemeral_pk);

    aes_decrypt(&aes_key, encrypted).map_err(|_| Error::DecryptionFailed)
}

fn generate_shared(secret: &SecretKey, public: &PublicKey) -> SharedSecret {
    let public = public.as_point();
    let secret = Scalar::from_bits(secret.to_bytes());
    let shared_point = public * secret;
    let shared_point = shared_point.compress();
    shared_point.as_bytes().to_owned()
}

fn encapsulate(emphemeral_sk: &SecretKey, peer_pk: &PublicKey) -> AesKey {
    let shared_point = generate_shared(emphemeral_sk, peer_pk);

    let emphemeral_pk = PublicKey::from_secret(emphemeral_sk);

    let mut master = Vec::with_capacity(32 * 2);
    master.extend(emphemeral_pk.0.as_bytes().iter());
    master.extend(shared_point.iter());
    hkdf_sha256(master.as_slice())
}

fn decapsulate(sk: &SecretKey, emphemeral_pk: &PublicKey) -> AesKey {
    let shared_point = generate_shared(sk, emphemeral_pk);

    let mut master = Vec::with_capacity(32 * 2);
    master.extend(emphemeral_pk.0.as_bytes().iter());
    master.extend(shared_point.iter());

    hkdf_sha256(master.as_slice())
}

/// Error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "ecies-rd25519: encryption failed")]
    EncryptionFailed,

    #[fail(display = "ecies-rd25519: encryption failed - RNG error")]
    EncryptionFailedRng,

    #[fail(display = "ecies-rd25519: decryption failed")]
    DecryptionFailed,

    #[fail(display = "ecies-rd25519: encryption failed - ciphertext too short")]
    DecryptionFailedCiphertextShort,

    #[fail(display = "ecies-rd25519: invalid public key bytes")]
    InvalidPublicKeyBytes,
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use rand::thread_rng;

    #[test]
    fn test_shared() {
        let (emphemeral_sk, emphemeral_pk) = generate_keypair(&mut thread_rng());
        let (peer_sk, peer_pk) = generate_keypair(&mut thread_rng());

        assert_eq!(
            generate_shared(&emphemeral_sk, &peer_pk),
            generate_shared(&peer_sk, &emphemeral_pk)
        );

        // Make sure it fails when wrong keys used
        assert_ne!(
            generate_shared(&emphemeral_sk, &emphemeral_pk),
            generate_shared(&peer_sk, &peer_pk)
        )
    }

    #[test]
    fn test_encapsulation() {
        let (emphemeral_sk, emphemeral_pk) = generate_keypair(&mut thread_rng());
        let (peer_sk, peer_pk) = generate_keypair(&mut thread_rng());

        assert_eq!(
            encapsulate(&emphemeral_sk, &peer_pk),
            decapsulate(&peer_sk, &emphemeral_pk)
        )
    }

    #[test]
    fn test_aes() {
        let mut key = [0u8; 32];
        thread_rng().fill_bytes(&mut key);

        let plaintext = b"ABOLISH ICE";
        let encrypted = aes_encrypt(&key, plaintext, &mut thread_rng()).unwrap();
        let decrypted = aes_decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_ecies_ed25519() {
        let (peer_sk, peer_pk) = generate_keypair(&mut thread_rng());

        let plaintext = b"ABOLISH ICE";

        let encrypted = encrypt(&peer_pk, plaintext, &mut thread_rng()).unwrap();
        let decrypted = decrypt(&peer_sk, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());

        // Test that it fails when using a bad secret key
        let (bad_sk, _) = generate_keypair(&mut thread_rng());
        assert!(decrypt(&bad_sk, &encrypted).is_err());
    }
}
