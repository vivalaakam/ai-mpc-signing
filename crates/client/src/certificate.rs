//! Certificate file for the auto-signer. The secret opens the local vault and
//! proves the login; mode 0600 keeps it as private as the database.

use std::path::Path;

use ai_signing_protocol::{CertificateFile, CertificateMaterial};

use crate::tighten;

pub fn save_certificate(path: &Path, file: &CertificateFile) -> Result<(), String> {
    if file.v != 1 {
        return Err("сертификат неизвестной версии".into());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("не удалось создать каталог сертификата: {err}"))?;
            tighten(parent, 0o700);
        }
    }
    let body = serde_json::to_string_pretty(file)
        .map_err(|err| format!("не удалось записать сертификат: {err}"))?;
    std::fs::write(path, body).map_err(|err| format!("не удалось записать сертификат: {err}"))?;
    tighten(path, 0o600);
    Ok(())
}

pub fn load_certificate(path: &Path) -> Result<CertificateMaterial, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("не удалось прочитать сертификат: {err}"))?;
    let file: CertificateFile =
        serde_json::from_str(&text).map_err(|_| "файл сертификата записан неверно".to_string())?;
    CertificateMaterial::from_file(&file).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn certificate_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ai-signing-cert-{}", Uuid::new_v4()));
        let path = dir.join("bot.json");
        let material = CertificateMaterial::generate("bot");
        let id = Uuid::new_v4();
        save_certificate(&path, &material.to_file(Some(id))).unwrap();
        let loaded = load_certificate(&path).unwrap();
        assert_eq!(loaded.username, "bot");
        assert_eq!(loaded.public_key_hex, material.public_key_hex);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
