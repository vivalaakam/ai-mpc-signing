use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::tighten;

const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub server: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            let config = Config {
                server: DEFAULT_SERVER.to_string(),
            };
            config.save(path)?;
            return Ok(config);
        }
        let text = std::fs::read_to_string(path)
            .map_err(|err| format!("не удалось прочитать конфиг: {err}"))?;
        let config: Config =
            toml::from_str(&text).map_err(|err| format!("конфиг записан неверно: {err}"))?;
        let server = normalize_server(&config.server)?;
        Ok(Config { server })
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|err| format!("не удалось создать каталог конфига: {err}"))?;
                tighten(parent, 0o700);
            }
        }
        let body = toml::to_string_pretty(self).map_err(|err| format!("конфиг: {err}"))?;
        std::fs::write(path, body).map_err(|err| format!("не удалось записать конфиг: {err}"))?;
        tighten(path, 0o600);
        Ok(())
    }

    pub fn server_url(&self) -> String {
        self.server.trim_end_matches('/').to_string()
    }
}

pub struct Launch {
    pub config_path: PathBuf,
    pub database_path: PathBuf,
    pub certificate_path: Option<PathBuf>,
    pub rest: Vec<String>,
}

pub fn parse_args<I, S>(args: I) -> Result<Launch, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut config = None;
    let mut database = None;
    let mut certificate = None;
    let mut rest = Vec::new();
    let mut args = args.into_iter().peekable();
    while let Some(arg) = args.next() {
        let arg = arg.as_ref();
        if let Some(path) = arg.strip_prefix("--config=") {
            set_once(&mut config, "--config", path)?;
        } else if arg == "--config" {
            let path = args
                .next()
                .ok_or_else(|| "у --config нет пути".to_string())?;
            set_once(&mut config, "--config", path.as_ref())?;
        } else if let Some(path) = arg.strip_prefix("--database=") {
            set_once(&mut database, "--database", path)?;
        } else if arg == "--database" {
            let path = args
                .next()
                .ok_or_else(|| "у --database нет пути".to_string())?;
            set_once(&mut database, "--database", path.as_ref())?;
        } else if let Some(path) = arg.strip_prefix("--certificate=") {
            set_once(&mut certificate, "--certificate", path)?;
        } else if arg == "--certificate" {
            let path = args
                .next()
                .ok_or_else(|| "у --certificate нет пути".to_string())?;
            set_once(&mut certificate, "--certificate", path.as_ref())?;
        } else if arg == "--help" || arg == "-h" {
            rest.push(arg.to_string());
        } else if arg.starts_with('-') {
            return Err(format!("неизвестный аргумент: {arg}"));
        } else {
            rest.push(arg.to_string());
        }
    }
    Ok(Launch {
        config_path: config
            .map(PathBuf::from)
            .unwrap_or_else(default_config_path),
        database_path: database
            .map(PathBuf::from)
            .unwrap_or_else(default_database_path),
        certificate_path: certificate.map(PathBuf::from),
        rest,
    })
}

pub fn default_config_path() -> PathBuf {
    if let Some(home) = home_override() {
        return home.join("config.toml");
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ai-signing")
        .join("config.toml")
}

pub fn default_database_path() -> PathBuf {
    if let Some(home) = home_override() {
        return home.join("client.sqlite");
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ai-signing")
        .join("client.sqlite")
}

/// Control socket next to the database. Linux sun_path holds at most 108 bytes.
pub fn socket_path_for(database: &Path) -> Result<PathBuf, String> {
    let mut name = database.as_os_str().to_owned();
    name.push(".sock");
    let path = PathBuf::from(name);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let len = path.as_os_str().as_bytes().len();
        if len >= 108 {
            return Err(format!(
                "путь к сокету слишком длинный ({len} байт, максимум 107): {}",
                path.display()
            ));
        }
    }
    Ok(path)
}

pub fn normalize_server(raw: &str) -> Result<String, String> {
    let server = raw.trim().trim_end_matches('/').to_string();
    let rest = if let Some(rest) = server.strip_prefix("https://") {
        rest
    } else if let Some(rest) = server.strip_prefix("http://") {
        rest
    } else {
        return Err("адрес сервера в конфиге должен начинаться с http:// или https://".to_string());
    };
    if rest.is_empty() || rest.contains(' ') {
        return Err("адрес сервера в конфиге указан неверно".to_string());
    }
    Ok(server)
}

fn home_override() -> Option<PathBuf> {
    std::env::var("AI_SIGNING_HOME")
        .ok()
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
}

fn set_once(slot: &mut Option<String>, flag: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("у {flag} нет пути"));
    }
    if slot.is_some() {
        return Err(format!("{flag} указан дважды"));
    }
    *slot = Some(value.to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_work_before_and_after_the_command() {
        let launch = parse_args([
            "--config",
            "/tmp/a.toml",
            "login",
            "ann",
            "--database=/tmp/a.sqlite",
        ])
        .unwrap();
        assert_eq!(launch.rest, vec!["login", "ann"]);
        assert_eq!(launch.config_path, PathBuf::from("/tmp/a.toml"));
        assert_eq!(launch.database_path, PathBuf::from("/tmp/a.sqlite"));
        assert!(launch.certificate_path.is_none());
    }

    #[test]
    fn certificate_flag_is_kept_apart_from_the_command() {
        let launch = parse_args([
            "--certificate",
            "/tmp/bot.json",
            "--database",
            "/tmp/bot.sqlite",
        ])
        .unwrap();
        assert!(launch.rest.is_empty());
        assert_eq!(
            launch.certificate_path.as_deref(),
            Some(Path::new("/tmp/bot.json"))
        );
    }

    #[test]
    fn config_roundtrip_normalizes_the_server() {
        let dir = std::env::temp_dir().join(format!("ai-signing-cfg-{}", uuid::Uuid::new_v4()));
        let path = dir.join("config.toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "server = \"http://127.0.0.1:9/\"\n").unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.server_url(), "http://127.0.0.1:9");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_config_is_created_with_the_default_server() {
        let dir = std::env::temp_dir().join(format!("ai-signing-cfg-{}", uuid::Uuid::new_v4()));
        let path = dir.join("nested").join("config.toml");
        let config = Config::load(&path).unwrap();
        assert_eq!(config.server_url(), DEFAULT_SERVER);
        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn long_socket_path_is_rejected() {
        let path = PathBuf::from(format!("/tmp/{}", "a".repeat(120)));
        let err = socket_path_for(&path).unwrap_err();
        assert!(err.contains("слишком длинный"), "{err}");
    }
}
