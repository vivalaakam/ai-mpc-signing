//! Shared client: config, local database, and the FROST session.
//!
//! The desktop window and the CLI both use this crate. One process per database
//! owns the ceremony and a unix socket. Other commands talk to that process.

mod config;
mod control;
mod session;
mod store;
mod vault;

pub use ai_signing_protocol::{
    message_text, recode_hex, role_title, GroupDto, SignRequestDto, SignerDto,
};
pub use config::{
    default_config_path, default_database_path, parse_args, socket_path_for, Config, Launch,
};
pub use control::{try_forward, Unlink};
pub use session::{execute, start, watch, Cmd, Reply, SettleWait, UiState};
pub use store::Store;

pub fn listen(
    database: &std::path::Path,
) -> Result<(std::os::unix::net::UnixListener, Unlink), String> {
    let path = socket_path_for(database)?;
    let listener = control::bind(&path)?;
    Ok((listener, Unlink(path)))
}

pub(crate) fn tighten(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    let _ = (path, mode);
}

/// Key shares are written to the database and to its WAL as ciphertext. Later
/// files in this process should stay private even when the parent directory is `/tmp`.
pub(crate) fn private_files() {
    #[cfg(unix)]
    // umask(2) меняет маску только этого процесса.
    unsafe {
        umask(0o077);
    }
}

#[cfg(unix)]
extern "C" {
    fn umask(mask: u32) -> u32;
}
