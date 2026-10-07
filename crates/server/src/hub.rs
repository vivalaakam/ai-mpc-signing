use std::{collections::HashMap, sync::Arc};

use ai_signing_protocol::ServerMsg;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct Hub {
    inner: Arc<Mutex<HashMap<Uuid, Vec<mpsc::UnboundedSender<String>>>>>,
}

impl Hub {
    pub async fn subscribe(&self, user: Uuid) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.lock().await.entry(user).or_default().push(tx);
        rx
    }

    pub async fn publish(&self, user: Uuid, message: &ServerMsg) {
        let Ok(text) = serde_json::to_string(message) else {
            return;
        };
        let mut guard = self.inner.lock().await;
        let Some(senders) = guard.get_mut(&user) else {
            return;
        };
        senders.retain(|sender| sender.send(text.clone()).is_ok());
        if senders.is_empty() {
            guard.remove(&user);
        }
    }

    pub async fn publish_all(&self, users: &[Uuid], message: &ServerMsg) {
        for user in users {
            self.publish(*user, message).await;
        }
    }
}
