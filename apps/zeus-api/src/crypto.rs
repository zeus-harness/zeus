use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, Payload},
};
use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::phc::PasswordHash};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

const AES_256_KEY_BYTES: usize = 32;
const AES_GCM_NONCE_BYTES: usize = 12;
type AesNonce = Nonce<<Aes256Gcm as AeadCore>::NonceSize>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("envelope key must contain exactly 32 bytes")]
    InvalidKeyLength,
    #[error("envelope key is not valid hexadecimal or base64")]
    InvalidKeyEncoding,
    #[error("secret encryption failed")]
    Encrypt,
    #[error("secret decryption failed")]
    Decrypt,
    #[error("secure random generation failed")]
    Random,
    #[error("secret hash could not be created")]
    Hash,
    #[error("secret hash is invalid")]
    InvalidHash,
}

pub trait EnvelopeCipher: Send + Sync {
    fn key_id(&self) -> &str;

    /// Encrypts a secret and binds it to `aad`.
    ///
    /// # Errors
    ///
    /// Returns an error when secure randomness or authenticated encryption fails.
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<SealedSecret, CryptoError>;

    /// Decrypts a secret after authenticating `aad`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed envelopes, unknown keys, or failed authentication.
    fn open(&self, sealed: &SealedSecret, aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub struct LocalEnvelopeCipher {
    cipher: Aes256Gcm,
    key_id: String,
}

impl LocalEnvelopeCipher {
    /// Builds the local AES-256-GCM implementation from a hex or base64 key.
    ///
    /// # Errors
    ///
    /// Returns an error when the key cannot be decoded to exactly 32 bytes.
    pub fn from_encoded(key_id: String, encoded_key: &SecretString) -> Result<Self, CryptoError> {
        let key = decode_key(encoded_key.expose_secret())?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(Self { cipher, key_id })
    }
}

impl EnvelopeCipher for LocalEnvelopeCipher {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<SealedSecret, CryptoError> {
        let mut nonce = [0_u8; AES_GCM_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::Random)?;
        let nonce_ref: &AesNonce = nonce
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Encrypt)?;
        let ciphertext = self
            .cipher
            .encrypt(
                nonce_ref,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Encrypt)?;
        Ok(SealedSecret {
            ciphertext,
            nonce: nonce.to_vec(),
            key_id: self.key_id.clone(),
        })
    }

    fn open(&self, sealed: &SealedSecret, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.key_id != self.key_id || sealed.nonce.len() != AES_GCM_NONCE_BYTES {
            return Err(CryptoError::Decrypt);
        }
        let nonce: &AesNonce = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Decrypt)?;
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed.ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Decrypt)
    }
}

#[must_use]
pub fn sha256(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}

/// Generates a URL-safe secret using operating-system randomness.
///
/// # Errors
///
/// Returns an error when the operating system cannot provide random bytes.
pub fn random_token(byte_count: usize) -> Result<SecretString, CryptoError> {
    let mut bytes = vec![0_u8; byte_count];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Random)?;
    Ok(SecretString::from(URL_SAFE_NO_PAD.encode(bytes)))
}

/// Hashes a service-account token using Argon2id and a fresh salt.
///
/// # Errors
///
/// Returns an error when randomness or password hashing fails.
pub fn hash_service_account_token(token: &SecretString) -> Result<String, CryptoError> {
    Argon2::default()
        .hash_password(token.expose_secret().as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|_| CryptoError::Hash)
}

#[must_use]
pub fn verify_service_account_token(token: &SecretString, encoded_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(token.expose_secret().as_bytes(), &parsed)
        .is_ok()
}

fn decode_key(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    let bytes = hex::decode(encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|_| CryptoError::InvalidKeyEncoding)?;
    if bytes.len() != AES_256_KEY_BYTES {
        return Err(CryptoError::InvalidKeyLength);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{
        EnvelopeCipher, LocalEnvelopeCipher, hash_service_account_token, random_token,
        verify_service_account_token,
    };

    #[test]
    fn envelope_round_trip_is_bound_to_aad() {
        let key = SecretString::from("11".repeat(32));
        let cipher = LocalEnvelopeCipher::from_encoded("local-v1".to_owned(), &key)
            .expect("valid local key");
        let sealed = cipher.seal(b"secret", b"connection/1").expect("encrypt");

        assert_eq!(
            cipher.open(&sealed, b"connection/1").expect("decrypt"),
            b"secret"
        );
        assert!(cipher.open(&sealed, b"connection/2").is_err());
    }

    #[test]
    fn service_account_hash_does_not_contain_the_token() {
        let token = random_token(32).expect("secure random token");
        let hash = hash_service_account_token(&token).expect("argon2 hash");

        assert!(!hash.contains(secrecy::ExposeSecret::expose_secret(&token)));
        assert!(verify_service_account_token(&token, &hash));
        assert!(!verify_service_account_token(
            &SecretString::from("wrong-token"),
            &hash
        ));
    }
}
