use rand::{CryptoRng, RngCore};
use ring::aead::*;
use ring::hkdf::*;

use super::AesKey;
use super::Error;
use super::AES_IV_LENGTH;
use super::HKDF_INFO;
use super::HKDF_SALT;

pub(crate) fn hkdf_sha256(master: &[u8]) -> AesKey {
    let salt = Salt::new(HKDF_SHA256, HKDF_SALT);
    let prk = salt.extract(master);
    let okm = prk
        .expand(&[HKDF_INFO], HKDF_SHA256)
        .expect("ecies-ed25519: unexpected prk error in ring hkdf_sha256");

    let mut out = [0u8; 32];
    okm.fill(&mut out)
        .expect("ecies-ed25519: unexpected okm error in ring hkdf_sha256");

    out
}

pub(crate) fn aes_encrypt<R: CryptoRng + RngCore>(
    key: &AesKey,
    msg: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    // Get the key into the correct form
    let key = UnboundKey::new(&AES_256_GCM, key).unwrap();
    let key = LessSafeKey::new(key);

    // Ring uses the same input variable as output
    let mut in_out = msg.to_owned();

    // The input/output variable need some space for a tag suffix
    for _ in 0..AES_256_GCM.tag_len() {
        in_out.push(0);
    }

    // Generate the nonce
    let mut nonce_bytes = [0u8; AES_IV_LENGTH];
    rng.try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| Error::EncryptionFailedRng)?;
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).expect("invalid `nonce` length");

    // Encrypt data into in_out variable
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| Error::EncryptionFailed)?;

    let mut output = Vec::with_capacity(AES_IV_LENGTH + in_out.len());
    output.extend(&nonce_bytes);
    output.extend(in_out);

    Ok(output)
}

pub(crate) fn aes_decrypt(key: &AesKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    // Get the key into the correct form
    let key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| Error::DecryptionFailed)?;
    let key = LessSafeKey::new(key);

    let nonce = &ciphertext[..AES_IV_LENGTH];
    let mut encrypted = ciphertext[AES_IV_LENGTH..].to_owned();
    dbg!(&encrypted);

    let nonce = Nonce::try_assume_unique_for_key(nonce).expect("invalid length of `nonce`");

    let output = key
        .open_in_place(nonce, Aad::empty(), &mut encrypted)
        .map_err(|_| Error::DecryptionFailed)?;

    // Truncate the tag off the end and return
    Ok(output[0..output.len() - 16].to_owned())
}
