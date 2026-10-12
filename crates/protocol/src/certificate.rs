//! Ed25519 certificate that stands in for a username and password.
//!
//! The admin registers the public key. The auto-signer keeps the secret key and
//! proves it on each login. The secret never goes to the server.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::Error;

#[derive(Clone, Serialize, Deserialize)]
pub struct CertificateFile {
    pub v: u8,
    pub username: String,
    pub public_key_hex: String,
    pub secret_key_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<Uuid>,
}

impl Drop for CertificateFile {
    fn drop(&mut self) {
        self.secret_key_hex.zeroize();
    }
}

/// Secret half of a certificate. Dropping it wipes the secret hex.
pub struct CertificateMaterial {
    pub username: String,
    pub public_key_hex: String,
    pub secret_key_hex: String,
}

impl Drop for CertificateMaterial {
    fn drop(&mut self) {
        self.secret_key_hex.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateLogin {
    pub username: String,
    pub public_key_hex: String,
    pub nonce: String,
    pub signed_at: i64,
    pub signature_hex: String,
}

impl CertificateMaterial {
    pub fn generate(username: impl Into<String>) -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let signing = SigningKey::from_bytes(&secret);
        let public = signing.verifying_key().to_bytes();
        let secret_key_hex = hex::encode(secret);
        secret.zeroize();
        Self {
            username: username.into(),
            public_key_hex: hex::encode(public),
            secret_key_hex,
        }
    }

    pub fn from_file(file: &CertificateFile) -> Result<Self, Error> {
        if file.v != 1 {
            return Err(Error::msg("сертификат неизвестной версии"));
        }
        let username = file.username.trim();
        if username.is_empty() {
            return Err(Error::msg("в сертификате нет имени"));
        }
        let mut secret = decode_key32(&file.secret_key_hex, "секрет сертификата")?;
        let signing = SigningKey::from_bytes(&secret);
        let derived = signing.verifying_key().to_bytes();
        secret.zeroize();
        let public = decode_key32(&file.public_key_hex, "публичный ключ сертификата")?;
        if derived != public {
            return Err(Error::msg(
                "секрет сертификата не совпадает с публичным ключом",
            ));
        }
        Ok(Self {
            username: username.to_string(),
            public_key_hex: hex::encode(public),
            secret_key_hex: hex::encode(signing.to_bytes()),
        })
    }

    pub fn to_file(&self, certificate_id: Option<Uuid>) -> CertificateFile {
        CertificateFile {
            v: 1,
            username: self.username.clone(),
            public_key_hex: self.public_key_hex.clone(),
            secret_key_hex: self.secret_key_hex.clone(),
            certificate_id,
        }
    }

    pub fn login_now(&self) -> Result<CertificateLogin, Error> {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let signed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::msg("часы системы отстают"))?
            .as_secs() as i64;
        self.login_proof(signed_at, &hex::encode(nonce))
    }

    pub fn login_proof(&self, signed_at: i64, nonce_hex: &str) -> Result<CertificateLogin, Error> {
        let mut secret = decode_key32(&self.secret_key_hex, "секрет сертификата")?;
        let signing = SigningKey::from_bytes(&secret);
        secret.zeroize();
        let message =
            certificate_login_message(&self.username, &self.public_key_hex, nonce_hex, signed_at);
        let signature = signing.sign(&message);
        Ok(CertificateLogin {
            username: self.username.clone(),
            public_key_hex: self.public_key_hex.clone(),
            nonce: nonce_hex.to_string(),
            signed_at,
            signature_hex: hex::encode(signature.to_bytes()),
        })
    }
}

pub fn certificate_login_message(
    username: &str,
    public_key_hex: &str,
    nonce_hex: &str,
    signed_at: i64,
) -> Vec<u8> {
    format!("ai-signing-cert-login-v1\n{username}\n{public_key_hex}\n{nonce_hex}\n{signed_at}")
        .into_bytes()
}

/// Checks that `login.public_key_hex` signed the canonical login statement.
pub fn verify_certificate_login(login: &CertificateLogin) -> Result<(), Error> {
    let public = decode_key32(&login.public_key_hex, "публичный ключ сертификата")?;
    let verifying = VerifyingKey::from_bytes(&public)
        .map_err(|_| Error::msg("публичный ключ сертификата указан неверно"))?;
    let signature = decode_key64(&login.signature_hex)?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature);
    let message = certificate_login_message(
        &login.username,
        &login.public_key_hex,
        &login.nonce,
        login.signed_at,
    );
    verifying
        .verify(&message, &signature)
        .map_err(|_| Error::msg("подпись сертификата не прошла проверку"))
}

pub fn canonical_public_key(hex_value: &str) -> Result<String, Error> {
    let public = decode_key32(hex_value, "публичный ключ сертификата")?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| Error::msg("публичный ключ сертификата указан неверно"))?;
    Ok(hex::encode(public))
}

fn decode_key32(hex_value: &str, what: &str) -> Result<[u8; 32], Error> {
    let bytes =
        hex::decode(hex_value.trim()).map_err(|_| Error::msg(format!("{what} не является hex")))?;
    bytes
        .try_into()
        .map_err(|_| Error::msg(format!("{what} должен быть 32 байта")))
}

fn decode_key64(hex_value: &str) -> Result<[u8; 64], Error> {
    let bytes = hex::decode(hex_value.trim())
        .map_err(|_| Error::msg("подпись сертификата не является hex"))?;
    bytes
        .try_into()
        .map_err(|_| Error::msg("подпись сертификата должна быть 64 байта"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_proof_verifies_and_rejects_a_changed_name() {
        let material = CertificateMaterial::generate("bot");
        let proof = material
            .login_proof(1_700_000_000, &"ab".repeat(16))
            .unwrap();
        verify_certificate_login(&proof).unwrap();

        let mut changed = proof.clone();
        changed.username = "other".into();
        assert!(verify_certificate_login(&changed).is_err());
    }

    #[test]
    fn file_roundtrip_keeps_the_same_public_key() {
        let material = CertificateMaterial::generate("bot");
        let restored = CertificateMaterial::from_file(&material.to_file(None)).unwrap();
        assert_eq!(restored.public_key_hex, material.public_key_hex);
        assert_eq!(restored.username, "bot");
        verify_certificate_login(&restored.login_now().unwrap()).unwrap();
    }
}
