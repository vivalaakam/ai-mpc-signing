//! Local secrets are sealed with a key derived from the user's password.
//!
//! The password is checked by the server on every login. The same password opens
//! this vault. The seed and the FROST shares never sit on disk as plaintext.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use ai_signing_protocol::HdIdentity;

use crate::store::Store;

const KDF_MEMORY_KIB: u32 = 19_456;
const KDF_TIME: u32 = 2;
const KDF_LANES: u32 = 1;
const SEED_AAD: &[u8] = b"ai-signing-seed-v1";
const SHARE_AAD: &[u8] = b"ai-signing-share-v1";

pub struct Vault {
    identity: HdIdentity,
    key: [u8; 32],
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Vault {
    /// Opens the vault for this database. Creates it when the user has none yet.
    /// A wrong password does not replace an existing vault.
    pub fn unlock_or_create(store: &Store, password: &str) -> Result<Self, String> {
        if password.is_empty() {
            return Err("введите пароль".into());
        }
        let vault = if let Some(record) = store.vault_record()? {
            Self::open(&record, password)?
        } else {
            let created = Self::create(password)?;
            store.save_vault_record(&created.1)?;
            created.0
        };
        store.delete_device_secret()?;
        Ok(vault)
    }

    pub fn identity(&self) -> &HdIdentity {
        &self.identity
    }

    pub fn seal_share(&self, plaintext: &str) -> Result<String, String> {
        seal(&self.key, SHARE_AAD, plaintext.as_bytes())
    }

    pub fn open_share(&self, packed: &str) -> Result<String, String> {
        let bytes = open(&self.key, SHARE_AAD, packed)?;
        String::from_utf8(bytes).map_err(|_| "доля ключа повреждена".into())
    }

    fn create(password: &str) -> Result<(Self, String), String> {
        let identity = HdIdentity::generate();
        let mut salt = [0u8; 16];
        fill(&mut salt);
        let key = derive(password, &salt)?;
        let secret = seal(&key, SEED_AAD, &identity.seed())?;
        let record = serde_json::to_string(&VaultRecord {
            v: 1,
            salt: hex::encode(salt),
            secret,
        })
        .map_err(|err| err.to_string())?;
        Ok((Self { identity, key }, record))
    }

    fn open(record: &str, password: &str) -> Result<Self, String> {
        let record: VaultRecord = serde_json::from_str(record)
            .map_err(|_| "локальное хранилище ключей повреждено".to_string())?;
        if record.v != 1 {
            return Err("локальное хранилище ключей неизвестной версии".into());
        }
        let salt = hex::decode(record.salt.trim())
            .map_err(|_| "локальное хранилище ключей повреждено".to_string())?;
        let key = derive(password, &salt)?;
        let mut seed_bytes = open(&key, SEED_AAD, &record.secret)
            .map_err(|_| "пароль не открывает локальные ключи".to_string())?;
        if seed_bytes.len() != 32 {
            seed_bytes.zeroize();
            return Err("локальное хранилище ключей повреждено".into());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        seed_bytes.zeroize();
        let identity = HdIdentity::from_seed(seed);
        seed.zeroize();
        Ok(Self { identity, key })
    }
}

#[derive(Serialize, Deserialize)]
struct VaultRecord {
    v: u8,
    salt: String,
    secret: String,
}

fn derive(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_TIME, KDF_LANES, Some(32))
        .map_err(|_| "не удалось подготовить пароль".to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| "не удалось обработать пароль".to_string())?;
    Ok(key)
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<String, String> {
    let mut nonce = [0u8; 24];
    fill(&mut nonce);
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| "не удалось зашифровать".to_string())?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "не удалось зашифровать".to_string())?;
    Ok(format!(
        "enc1:{}:{}",
        hex::encode(nonce),
        hex::encode(ciphertext)
    ))
}

fn open(key: &[u8; 32], aad: &[u8], packed: &str) -> Result<Vec<u8>, String> {
    let mut parts = packed.split(':');
    let version = parts.next().unwrap_or("");
    let nonce_hex = parts.next().unwrap_or("");
    let cipher_hex = parts.next().unwrap_or("");
    if version != "enc1" || parts.next().is_some() {
        return Err("локальные данные повреждены".into());
    }
    let nonce = hex::decode(nonce_hex).map_err(|_| "локальные данные повреждены".to_string())?;
    let ciphertext =
        hex::decode(cipher_hex).map_err(|_| "локальные данные повреждены".to_string())?;
    if nonce.len() != 24 {
        return Err("локальные данные повреждены".into());
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "не удалось расшифровать".to_string())?;
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| "не удалось расшифровать".to_string())
}

fn fill(bytes: &mut [u8]) {
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn password_opens_the_same_seed_and_rejects_another() {
        let dir = std::env::temp_dir().join(format!("ai-signing-vault-{}", Uuid::new_v4()));
        let store = Store::open_path(&dir.join("client.sqlite")).unwrap();
        let vault = Vault::unlock_or_create(&store, "password1").unwrap();
        let account = vault.identity().account_key().public_hex();
        let group = Uuid::new_v4();
        let group_key = vault.identity().group_key(group).public_hex();
        drop(vault);

        let again = Vault::unlock_or_create(&store, "password1").unwrap();
        assert_eq!(again.identity().account_key().public_hex(), account);
        assert_eq!(again.identity().group_key(group).public_hex(), group_key);
        let stored = store.vault_record().unwrap().unwrap();
        assert!(!stored.contains(&hex::encode(again.identity().seed())));
        drop(again);

        match Vault::unlock_or_create(&store, "password2") {
            Ok(_) => panic!("чужой пароль открыл хранилище"),
            Err(err) => assert_eq!(err, "пароль не открывает локальные ключи"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn share_ciphertext_does_not_contain_the_secret() {
        let dir = std::env::temp_dir().join(format!("ai-signing-share-{}", Uuid::new_v4()));
        let store = Store::open_path(&dir.join("client.sqlite")).unwrap();
        let vault = Vault::unlock_or_create(&store, "password1").unwrap();
        let user = Uuid::new_v4();
        let group = Uuid::new_v4();
        let blob = ai_signing_protocol::ParticipantBlobDto {
            dkg: None,
            key: Some("share-secret".into()),
            pubkey: Some("pub".into()),
            signs: vec![],
        };
        store.save_share(user, group, &blob, &vault).unwrap();
        let path = dir.join("client.sqlite");
        let mut disk = std::fs::read(&path).unwrap();
        for suffix in ["-wal", "-shm"] {
            let side = path.with_file_name(format!(
                "{}{suffix}",
                path.file_name().unwrap().to_string_lossy()
            ));
            if let Ok(extra) = std::fs::read(&side) {
                disk.extend(extra);
            }
        }
        assert!(
            !disk
                .windows(b"share-secret".len())
                .any(|chunk| chunk == b"share-secret"),
            "доля лежит на диске открытым текстом"
        );
        let loaded = store.load_share(user, group, &vault).unwrap().unwrap();
        assert_eq!(loaded.key.as_deref(), Some("share-secret"));
        drop(vault);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
