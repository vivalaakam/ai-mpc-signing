use std::path::Path;
use std::time::Duration;

use ai_signing_protocol::ParticipantBlobDto;
use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use crate::config::default_database_path;
use crate::vault::Vault;
use crate::{private_files, tighten};

const TOKEN: &str = "token";
const USER_ID: &str = "user_id";
const USERNAME: &str = "username";
const ROLE: &str = "role";
const DEVICE_SECRET: &str = "device_secret";
const VAULT: &str = "vault";

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open() -> Result<Self, String> {
        Self::open_path(&default_database_path())
    }

    pub fn open_path(path: &Path) -> Result<Self, String> {
        private_files();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|err| format!("не удалось создать каталог базы: {err}"))?;
                tighten(parent, 0o700);
            }
        }
        let conn = Connection::open(path).map_err(|err| format!("локальная база: {err}"))?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|err| err.to_string())?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|err| format!("локальная база: {err}"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shares (
                user_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                blob TEXT NOT NULL,
                PRIMARY KEY (user_id, group_id)
            );",
        )
        .map_err(|err| err.to_string())?;
        tighten(path, 0o600);
        for suffix in ["-wal", "-shm"] {
            let mut side = path.as_os_str().to_owned();
            side.push(suffix);
            tighten(Path::new(&side), 0o600);
        }
        Ok(Self { conn })
    }

    pub fn session(&self) -> Option<(String, Uuid, String)> {
        let token = self.get_kv(TOKEN).ok().flatten()?;
        let user_id = self.get_kv(USER_ID).ok().flatten()?.parse().ok()?;
        let username = self.get_kv(USERNAME).ok().flatten()?;
        if token.is_empty() || username.is_empty() {
            return None;
        }
        Some((token, user_id, username))
    }

    pub fn role(&self) -> Option<String> {
        self.get_kv(ROLE)
            .ok()
            .flatten()
            .filter(|role| !role.is_empty())
    }

    pub fn save_session(
        &self,
        token: &str,
        user_id: Uuid,
        username: &str,
        role: &str,
    ) -> Result<(), String> {
        self.set_kv(TOKEN, token)?;
        self.set_kv(USER_ID, &user_id.to_string())?;
        self.set_kv(USERNAME, username)?;
        self.set_kv(ROLE, role)
    }

    pub fn clear_session(&self) -> Result<(), String> {
        self.delete_kv(TOKEN)?;
        self.delete_kv(USER_ID)?;
        self.delete_kv(USERNAME)?;
        self.delete_kv(ROLE)
    }

    pub fn vault_record(&self) -> Result<Option<String>, String> {
        self.get_kv(VAULT)
    }

    pub fn save_vault_record(&self, record: &str) -> Result<(), String> {
        self.set_kv(VAULT, record)
    }

    /// Removes a device secret left from a build that stored it in the clear.
    pub fn delete_device_secret(&self) -> Result<(), String> {
        self.delete_kv(DEVICE_SECRET)
    }

    pub fn load_share(
        &self,
        user_id: Uuid,
        group_id: Uuid,
        vault: &Vault,
    ) -> Result<Option<ParticipantBlobDto>, String> {
        let stored: Option<String> = self
            .conn
            .query_row(
                "SELECT blob FROM shares WHERE user_id = ?1 AND group_id = ?2",
                (user_id.to_string(), group_id.to_string()),
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| err.to_string())?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        if stored.trim_start().starts_with('{') {
            let blob = serde_json::from_str(&stored).map_err(|err| err.to_string())?;
            self.save_share(user_id, group_id, &blob, vault)?;
            return Ok(Some(blob));
        }
        let json = vault.open_share(&stored)?;
        serde_json::from_str(&json)
            .map(Some)
            .map_err(|err| err.to_string())
    }

    pub fn save_share(
        &self,
        user_id: Uuid,
        group_id: Uuid,
        blob: &ParticipantBlobDto,
        vault: &Vault,
    ) -> Result<(), String> {
        let json = serde_json::to_string(blob).map_err(|err| err.to_string())?;
        let sealed = vault.seal_share(&json)?;
        self.conn
            .execute(
                "INSERT INTO shares (user_id, group_id, blob) VALUES (?1, ?2, ?3)
                 ON CONFLICT(user_id, group_id) DO UPDATE SET blob = excluded.blob",
                (user_id.to_string(), group_id.to_string(), sealed),
            )
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    fn get_kv(&self, key: &str) -> Result<Option<String>, String> {
        self.conn
            .query_row("SELECT value FROM kv WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|err| err.to_string())
    }

    fn set_kv(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO kv (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    fn delete_kv(&self, key: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM kv WHERE key = ?1", [key])
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_roundtrip_stays_on_disk() {
        let dir = std::env::temp_dir().join(format!("ai-signing-db-{}", Uuid::new_v4()));
        let path = dir.join("nested").join("client.sqlite");
        let store = Store::open_path(&path).unwrap();
        let vault = crate::vault::Vault::unlock_or_create(&store, "password1").unwrap();
        let user = Uuid::new_v4();
        let group = Uuid::new_v4();
        let blob = ParticipantBlobDto {
            dkg: None,
            key: Some("share".into()),
            pubkey: Some("pub".into()),
            signs: vec![],
        };
        store.save_share(user, group, &blob, &vault).unwrap();
        let loaded = store.load_share(user, group, &vault).unwrap().unwrap();
        assert_eq!(loaded.key.as_deref(), Some("share"));
        assert!(store
            .load_share(user, Uuid::new_v4(), &vault)
            .unwrap()
            .is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let wal = path.with_file_name(format!(
                "{}-wal",
                path.file_name().unwrap().to_string_lossy()
            ));
            if wal.exists() {
                let wal_mode = std::fs::metadata(&wal).unwrap().permissions().mode();
                assert_eq!(wal_mode & 0o777, 0o600);
            }
        }
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
