use std::path::{Path, PathBuf};
use std::time::Duration;

use async_channel::Sender;
use std::os::unix::net::UnixListener as StdUnixListener;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::session::{Job, Reply};
use crate::tighten;

pub struct Unlink(pub PathBuf);

impl Drop for Unlink {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn bind(path: &Path) -> Result<StdUnixListener, String> {
    if path.exists() {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(stream) => {
                drop(stream);
                return Err("клиент уже запущен".into());
            }
            Err(_) => {
                std::fs::remove_file(path)
                    .map_err(|err| format!("не удалось убрать старый сокет: {err}"))?;
            }
        }
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("не удалось создать каталог сокета: {err}"))?;
        }
    }
    let listener = StdUnixListener::bind(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AddrInUse {
            "клиент уже запущен".to_string()
        } else {
            format!("сокет управления: {err}")
        }
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("сокет управления: {err}"))?;
    tighten(path, 0o600);
    Ok(listener)
}

/// Registers a std listener with the current Tokio runtime.
pub fn into_tokio(listener: StdUnixListener) -> Result<UnixListener, String> {
    UnixListener::from_std(listener).map_err(|err| format!("сокет управления: {err}"))
}

pub async fn accept(listener: UnixListener, tx: Sender<Job>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _ = handle_conn(stream, tx).await;
                });
            }
            Err(_) => break,
        }
    }
}

async fn handle_conn(stream: UnixStream, tx: Sender<Job>) -> Result<(), ()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let line = match lines.next_line().await {
        Ok(Some(line)) => line,
        _ => return Err(()),
    };
    let reply = match serde_json::from_str::<crate::Cmd>(&line) {
        Ok(cmd) => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            tx.send(Job {
                cmd,
                reply: Some(reply_tx),
                wait: None,
            })
            .await
            .map_err(|_| ())?;
            reply_rx.await.map_err(|_| ())?
        }
        Err(_) => Reply::fatal("", "непонятная команда"),
    };
    let mut text = serde_json::to_string(&reply).map_err(|_| ())?;
    text.push('\n');
    write.write_all(text.as_bytes()).await.map_err(|_| ())?;
    Ok(())
}

/// Forwards one command when a client is already listening.
/// `Ok(None)` means the socket is absent or stale and was removed.
pub fn try_forward(path: &Path, cmd: &crate::Cmd) -> Result<Option<Reply>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let mut stream = match std::os::unix::net::UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(_) => {
            let _ = std::fs::remove_file(path);
            return Ok(None);
        }
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    use std::io::{BufRead, Write};
    let mut line = serde_json::to_string(cmd).map_err(|err| format!("команда: {err}"))?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|err| format!("клиент не принял команду: {err}"))?;
    let mut reader = std::io::BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|err| format!("клиент не ответил: {err}"))?;
    if response.is_empty() {
        return Err("клиент закрыл ответ".into());
    }
    serde_json::from_str(&response)
        .map_err(|err| format!("ответ клиента: {err}: {response}"))
        .map(Some)
}
