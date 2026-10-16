use ai_signing_protocol::{ClientMsg, ServerMsg};
use axum::{
    extract::{ws::Message, Query, State, WebSocketUpgrade},
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use uuid::Uuid;

use crate::{ceremony, db, error::ApiError, AppState};

#[derive(Deserialize)]
pub struct TokenQuery {
    token: String,
}

pub async fn upgrade(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, ApiError> {
    let user = db::user_by_token(&state.pool, &query.token)
        .await
        .map_err(ApiError::db)?;
    let Some((user_id, username, _role)) = user else {
        return Err(ApiError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "сессия не найдена",
        ));
    };
    Ok(ws.on_upgrade(move |socket| connected(state, user_id, username, socket)))
}

async fn connected(
    state: AppState,
    user_id: Uuid,
    username: String,
    socket: axum::extract::ws::WebSocket,
) {
    let mut outbound = state.hub.subscribe(user_id).await;
    let (mut sink, mut stream) = socket.split();
    let snapshot = async {
        let ids = db::list_group_ids(&state.pool, user_id).await?;
        let mut groups = Vec::new();
        for id in ids {
            groups.push(db::load_group(&state.pool, id, user_id).await?);
        }
        let requests = db::list_requests(&state.pool, user_id).await?;
        let mut replay = ceremony::replay(&state, user_id)
            .await
            .map_err(|err| sqlx::Error::Protocol(err.message))?;
        replay.extend(
            crate::reshare::replay(&state, user_id)
                .await
                .map_err(|err| sqlx::Error::Protocol(err.message))?,
        );
        Ok::<_, sqlx::Error>((groups, requests, replay))
    };
    let Ok((groups, requests, replay)) = snapshot.await else {
        let _ = sink
            .send(Message::Text(
                serde_json::to_string(&ServerMsg::Error {
                    message: "не удалось собрать состояние".into(),
                })
                .unwrap_or_default()
                .into(),
            ))
            .await;
        return;
    };
    let forming_group_ids: Vec<Uuid> = groups
        .iter()
        .filter(|group| group.status == "forming")
        .map(|group| group.id)
        .collect();
    let resharing_group_ids: Vec<Uuid> = groups
        .iter()
        .filter(|group| group.status == "resharing")
        .map(|group| group.id)
        .collect();
    let hello = ServerMsg::Hello { user_id, username };
    let snap = ServerMsg::Snapshot { groups, requests };
    if send_msg(&mut sink, &hello).await.is_err() || send_msg(&mut sink, &snap).await.is_err() {
        return;
    }
    for message in replay {
        if send_msg(&mut sink, &message).await.is_err() {
            return;
        }
    }
    for group_id in forming_group_ids {
        ceremony::maybe_auto_start_dkg(&state, group_id).await;
    }
    for group_id in resharing_group_ids {
        crate::reshare::maybe_auto_start_reshare(&state, group_id).await;
    }

    loop {
        tokio::select! {
            incoming = stream.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if let Err(err) = handle_text(&state, user_id, text.as_str()).await {
                            let _ = send_msg(&mut sink, &ServerMsg::Error { message: err.message }).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            outgoing = outbound.recv() => {
                match outgoing {
                    Some(text) => {
                        if sink.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

async fn send_msg(
    sink: &mut futures::stream::SplitSink<axum::extract::ws::WebSocket, Message>,
    message: &ServerMsg,
) -> Result<(), ()> {
    let text = serde_json::to_string(message).map_err(|_| ())?;
    sink.send(Message::Text(text.into())).await.map_err(|_| ())
}

async fn handle_text(state: &AppState, user: Uuid, text: &str) -> Result<(), ApiError> {
    let message: ClientMsg =
        serde_json::from_str(text).map_err(|_| crate::error::bad("неизвестное сообщение"))?;
    match message {
        ClientMsg::DkgRound1 { group_id, package } => {
            ceremony::dkg_round1(state, user, group_id, package).await
        }
        ClientMsg::DkgRound2 { group_id, packages } => {
            ceremony::dkg_round2(state, user, group_id, packages).await
        }
        ClientMsg::DkgPublic {
            group_id,
            public_key_package,
        } => ceremony::dkg_public(state, user, group_id, public_key_package).await,
        ClientMsg::DkgAbort { group_id, reason } => {
            ceremony::dkg_abort(state, user, group_id, reason).await
        }
        ClientMsg::SignApprove { request_id } => {
            ceremony::decide(state, user, request_id, true).await
        }
        ClientMsg::SignReject { request_id } => {
            ceremony::decide(state, user, request_id, false).await
        }
        ClientMsg::SignCommitment {
            request_id,
            commitment,
        } => ceremony::sign_commitment(state, user, request_id, commitment).await,
        ClientMsg::SignShare { request_id, share } => {
            ceremony::sign_share(state, user, request_id, share).await
        }
        ClientMsg::SignAbort { request_id, reason } => {
            ceremony::sign_abort(state, user, request_id, reason).await
        }
        ClientMsg::ReshareRound1 { group_id, package } => {
            crate::reshare::round1(state, user, group_id, package).await
        }
        ClientMsg::ReshareRound2 { group_id, packages } => {
            crate::reshare::round2(state, user, group_id, packages).await
        }
        ClientMsg::ReshareRefreshPublic {
            group_id,
            public_key_package,
        } => crate::reshare::refresh_public(state, user, group_id, public_key_package).await,
        ClientMsg::ReshareDelta {
            group_id,
            joiner,
            packages,
        } => crate::reshare::delta(state, user, group_id, joiner, packages).await,
        ClientMsg::ReshareSigma {
            group_id,
            joiner,
            ciphertext,
            commitment,
        } => crate::reshare::sigma(state, user, group_id, joiner, ciphertext, commitment).await,
        ClientMsg::ReshareVerifying {
            group_id,
            joiner,
            verifying_share,
        } => crate::reshare::verifying(state, user, group_id, joiner, verifying_share).await,
        ClientMsg::ResharePublic {
            group_id,
            public_key_package,
        } => crate::reshare::final_public(state, user, group_id, public_key_package).await,
        ClientMsg::ReshareAbort { group_id, reason } => {
            crate::reshare::abort(state, user, group_id, reason).await
        }
    }
}
