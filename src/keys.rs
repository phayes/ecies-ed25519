use super::Error;
use core::iter::FromIterator;
use curve25519_dalek::constants;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use hex::{FromHex, ToHex};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// The length of a `SecretKey`, in bytes.
pub const SECRET_KEY_LENGTH: usize = 32;

/// The length of a `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Secret Key
///
/// Neither this secret key (nor it's corresponding PublicKey) should be used for signing
/// or in any other protocol other than ECIES.
#[derive(Debug)]
pub struct SecretKey(pub(crate) [u8; SECRET_KEY_LENGTH]);

/// Zero a secretKey when it's dropped
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ToHex for SecretKey {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        self.0.encode_hex()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        self.0.encode_hex_upper()
    }
}

impl FromHex for SecretKey {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Error> {
        let mut bytes = Vec::<u8>::from_hex(hex).map_err(|_| Error::InvalidSecretKeyBytes)?;
        let sk = Self::from_bytes(&bytes)?;
        bytes.zeroize();
        Ok(sk)
    }
}

impl SecretKey {
    /// Convert this secret key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0
    }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    /// Construct a `SecretKey` from a slice of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use ecies_ed25519::SecretKey;
    /// use ecies_ed25519::SECRET_KEY_LENGTH;
    /// use ecies_ed25519::Error;
    ///
    /// # fn doctest() -> Result<SecretKey, Error> {
    /// let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
    ///    157, 097, 177, 157, 239, 253, 090, 096,
    ///    186, 132, 074, 244, 146, 236, 044, 196,
    ///    068, 073, 197, 105, 123, 050, 105, 025,
    ///    112, 059, 172, 003, 028, 174, 127, 096, ];
    ///
    /// let secret_key: SecretKey = SecretKey::from_bytes(&secret_key_bytes)?;
    /// #
    /// # Ok(secret_key)
    /// # }
    /// #
    /// # fn main() {
    /// #     let result = doctest();
    /// #     assert!(result.is_ok());
    /// # }
    /// ```
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, Error> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(Error::InvalidSecretKeyBytes);
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(SecretKey(bits))
    }

    /// Generate a `SecretKey` from a `csprng`.
    pub fn generate<T>(csprng: &mut T) -> SecretKey
    where
        T: CryptoRng + RngCore,
    {
        let mut sk: SecretKey = SecretKey([0u8; 32]);
        csprng.fill_bytes(&mut sk.0);
        sk
    }
}

/// Public Key
///
/// Neither this public key (nor it's corresponding  PrivateKey) should be used for signing
/// or in any other protocol other than ECIES.
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct PublicKey(pub(crate) CompressedEdwardsY);

impl PublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// Will return None if the bytes are invalid
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(Error::InvalidPublicKeyBytes);
        }

        let point = CompressedEdwardsY::from_slice(bytes);

        if point.decompress().is_none() {
            return Err(Error::InvalidPublicKeyBytes);
        }
        Ok(PublicKey(point))
    }

    /// Derive a public key from a private key
    pub fn from_secret(sk: &SecretKey) -> Self {
        let point = &Scalar::from_bits(sk.to_bytes()) * &constants::ED25519_BASEPOINT_TABLE;
        PublicKey(point.compress())
    }

    /// Get the Edwards Point for this public key
    pub fn to_point(&self) -> EdwardsPoint {
        CompressedEdwardsY::from_slice(self.0.as_bytes())
            .decompress()
            .expect("ecies-ed25519: unexpect error decompressing public key")
    }
}

// Note: ToHex is implemented implicitly through impl AsRef<[u8]> for PublicKey
impl FromHex for PublicKey {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Error> {
        let mut bytes = Vec::<u8>::from_hex(hex).map_err(|_| Error::InvalidPublicKeyBytes)?;
        let sk = Self::from_bytes(&bytes)?;
        bytes.zeroize();
        Ok(sk)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

// "serde" feature
// ---------------

#[cfg(feature = "serde")]
use serde::{
    de::Error as SerdeError, de::Unexpected, de::Visitor, Deserialize, Deserializer, Serialize,
    Serializer,
};

#[cfg(feature = "serde")]
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let encoded: Vec<char> = self.encode_hex();
            let mut encoded: String = encoded.into_iter().collect();
            let result = serializer.serialize_str(&encoded);

            encoded.zeroize();

            result
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct SecretKeyVisitor;

        impl<'d> Visitor<'d> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An ecies-ed25519 secret key as 32 bytes.")
            }

            fn visit_str<E>(self, input: &str) -> Result<SecretKey, E>
            where
                E: SerdeError,
            {
                let mut bytes = hex::decode(input).or(Err(SerdeError::invalid_value(
                    Unexpected::Other("invalid hex"),
                    &self,
                )))?;
                let sk = SecretKey::from_bytes(&bytes)
                    .or(Err(SerdeError::invalid_length(bytes.len(), &self)))?;
                bytes.zeroize();
                Ok(sk)
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<SecretKey, E>
            where
                E: SerdeError,
            {
                SecretKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(SecretKeyVisitor)
        } else {
            deserializer.deserialize_bytes(SecretKeyVisitor)
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let encoded: Vec<char> = self.encode_hex();
            let mut encoded: String = encoded.into_iter().collect();
            let result = serializer.serialize_str(&encoded);

            encoded.zeroize();

            result
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct PublicKeyVisitor;

        impl<'d> Visitor<'d> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An ecies-ed25519 public key as 32 bytes.")
            }

            fn visit_str<E>(self, input: &str) -> Result<PublicKey, E>
            where
                E: SerdeError,
            {
                if input.len() != PUBLIC_KEY_LENGTH * 2 {
                    return Err(SerdeError::invalid_length(input.len(), &self));
                }
                let mut bytes = hex::decode(input).or(Err(SerdeError::invalid_value(
                    Unexpected::Other("invalid hex"),
                    &self,
                )))?;
                let pk = PublicKey::from_bytes(&bytes).map_err(|e| SerdeError::custom(e))?;
                bytes.zeroize();
                Ok(pk)
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<PublicKey, E>
            where
                E: SerdeError,
            {
                if bytes.len() != PUBLIC_KEY_LENGTH {
                    return Err(SerdeError::invalid_length(bytes.len(), &self));
                }
                PublicKey::from_bytes(bytes).map_err(|e| SerdeError::custom(e))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(PublicKeyVisitor)
        } else {
            deserializer.deserialize_bytes(PublicKeyVisitor)
        }
    }
}
