//! Share refresh. The server relays sealed packages and checks that every
//! published group key is the same verifying key with the new committee.
//! It never sees a signing share.

use ai_signing_protocol::{
    canonical_public_package, package_signer_ids, package_verifying_key_hex, RosterKey,
    SealedPackage, ServerMsg,
};
use axum::http::StatusCode;
use uuid::Uuid;

use crate::{
    ceremony::publish_group,
    db::{self, check_package},
    error::{bad, ApiError},
    AppState,
};

#[derive(sqlx::FromRow)]
struct RosterMember {
    identifier: i32,
    role: String,
    box_public: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    generation: i32,
    phase: String,
    threshold: i32,
    refresh_package: Option<String>,
}

pub async fn start(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    add: Vec<String>,
    remove: Vec<String>,
) -> Result<(), ApiError> {
    let group = db::load_group(&state.pool, group_id, user)
        .await
        .map_err(ApiError::db)?;
    if !group.i_created {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "пересчитывать доли может создатель группы",
        ));
    }
    let add = names(&add)?;
    let remove = names(&remove)?;
    if add.is_empty() && remove.is_empty() {
        return Err(bad("укажите, кого добавить или удалить"));
    }
    if add
        .iter()
        .any(|name| remove.iter().any(|other| other == name))
    {
        return Err(bad(
            "нельзя одновременно добавить и удалить одного участника",
        ));
    }
    let mut tx = state.pool.begin().await.map_err(ApiError::db)?;
    let status: String = sqlx::query_scalar("SELECT status FROM groups WHERE id = $1 FOR UPDATE")
        .bind(group_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    if status != "active" {
        let message = match status.as_str() {
            "resharing" => "дождитесь завершения текущего пересчёта долей",
            "dkg" => "дождитесь завершения генерации ключа",
            _ => "пересчёт долей доступен только активной группе",
        };
        return Err(bad(message));
    }
    let reshare_busy: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM reshare_sessions WHERE group_id = $1)",
    )
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    if reshare_busy {
        return Err(bad("дождитесь завершения текущего пересчёта долей"));
    }
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM signing_requests
            WHERE group_id = $1 AND status IN ('pending', 'signing')
         )",
    )
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    if busy {
        return Err(bad("дождитесь завершения текущей подписи"));
    }
    let members: Vec<(Uuid, String, i32, Option<String>)> = sqlx::query_as(
        "SELECT gm.user_id, u.username, gm.identifier, gm.box_public
         FROM group_members gm
         JOIN users u ON u.id = gm.user_id
         WHERE gm.group_id = $1
         ORDER BY gm.identifier",
    )
    .bind(group_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    let mut leaving = Vec::new();
    for name in &remove {
        let Some(member) = members.iter().find(|member| &member.1 == name) else {
            return Err(bad(format!("пользователь {name} не в группе")));
        };
        leaving.push(member.0);
    }
    let stayers: Vec<&(Uuid, String, i32, Option<String>)> = members
        .iter()
        .filter(|member| !leaving.contains(&member.0))
        .collect();
    let final_size = stayers.len() + add.len();
    if final_size < usize::from(group.threshold) {
        return Err(bad(
            "после изменения состава должно остаться не меньше участников, чем порог t",
        ));
    }
    if stayers.len() < usize::from(group.threshold) {
        return Err(bad("после удаления участников порог должен выполняться"));
    }
    if final_size > 16 {
        return Err(bad("в группе не больше 16 участников"));
    }
    for member in &stayers {
        if member.3.is_none() {
            return Err(bad(format!(
                "у {} ещё нет ключа для этой группы: пусть этот пользователь откроет приложение",
                member.1
            )));
        }
    }
    let mut next_identifier: i32 = members.iter().map(|member| member.2).max().unwrap_or(0);
    let mut joiners = Vec::new();
    for name in &add {
        if members.iter().any(|member| &member.1 == name) {
            return Err(bad(format!("пользователь {name} уже в группе")));
        }
        let signer = active_signer(&mut *tx, name).await?;
        next_identifier += 1;
        if next_identifier <= 0 || next_identifier > i32::from(u16::MAX) {
            return Err(bad("закончились идентификаторы участников"));
        }
        sqlx::query(
            "INSERT INTO group_members (group_id, user_id, identifier, accepted_at)
             VALUES ($1, $2, $3, NULL)",
        )
        .bind(group_id)
        .bind(signer)
        .bind(next_identifier)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::db)?;
        joiners.push((signer, next_identifier));
    }
    let generation: i32 = sqlx::query_scalar(
        "UPDATE groups SET status = 'resharing', share_generation = share_generation + 1
         WHERE id = $1 AND status = 'active'
         RETURNING share_generation",
    )
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    sqlx::query(
        "INSERT INTO reshare_sessions (group_id, generation, phase, threshold)
         VALUES ($1, $2, 'waiting', $3)",
    )
    .bind(group_id)
    .bind(generation)
    .bind(i32::from(group.threshold))
    .execute(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    for member in &stayers {
        sqlx::query(
            "INSERT INTO reshare_roster (group_id, user_id, identifier, role)
             VALUES ($1, $2, $3, 'stayer')",
        )
        .bind(group_id)
        .bind(member.0)
        .bind(member.2)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    }
    for (signer, identifier) in &joiners {
        sqlx::query(
            "INSERT INTO reshare_roster (group_id, user_id, identifier, role)
             VALUES ($1, $2, $3, 'joiner')",
        )
        .bind(group_id)
        .bind(signer)
        .bind(identifier)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    }
    tx.commit().await.map_err(ApiError::db)?;
    publish_group(state, group_id).await?;
    maybe_auto_start_reshare(state, group_id).await;
    Ok(())
}

async fn reshare_consents_ready(state: &AppState, group_id: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM reshare_sessions WHERE group_id = $1 AND phase = 'waiting')
         AND NOT EXISTS (
            SELECT 1 FROM reshare_roster r
            JOIN group_members gm ON gm.group_id = r.group_id AND gm.user_id = r.user_id
            WHERE r.group_id = $1
              AND (
                (r.role = 'joiner' AND (gm.accepted_at IS NULL OR gm.box_public IS NULL))
                OR (r.role = 'stayer' AND gm.box_public IS NULL)
              )
         )",
    )
    .bind(group_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false)
}

async fn roster_user_ids(state: &AppState, group_id: Uuid) -> Result<Vec<Uuid>, ApiError> {
    sqlx::query_scalar("SELECT user_id FROM reshare_roster WHERE group_id = $1 ORDER BY identifier")
        .bind(group_id)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::db)
}

pub async fn maybe_auto_start_reshare(state: &AppState, group_id: Uuid) {
    if !reshare_consents_ready(state, group_id).await {
        return;
    }
    let Ok(roster) = roster_user_ids(state, group_id).await else {
        return;
    };
    if !state.hub.all_online(&roster).await {
        return;
    }
    let updated = sqlx::query(
        "UPDATE reshare_sessions SET phase = 'refresh' WHERE group_id = $1 AND phase = 'waiting'",
    )
    .bind(group_id)
    .execute(&state.pool)
    .await;
    let Ok(result) = updated else {
        return;
    };
    if result.rows_affected() == 1 {
        tracing::info!(%group_id, "пересчёт долей: фаза refresh");
        let _ = publish_started(state, group_id).await;
    }
}

pub async fn note_device(state: &AppState, group_id: Uuid) -> Result<(), ApiError> {
    maybe_auto_start_reshare(state, group_id).await;
    Ok(())
}

pub async fn is_reshare_joiner(
    state: &AppState,
    group_id: Uuid,
    user_id: Uuid,
) -> Result<bool, ApiError> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM reshare_roster WHERE group_id = $1 AND user_id = $2",
    )
    .bind(group_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(role.as_deref() == Some("joiner"))
}

pub async fn round1(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    package: String,
) -> Result<(), ApiError> {
    check_package(&package)?;
    let Some((identifier, role)) = roster_member(state, group_id, user).await? else {
        return Ok(());
    };
    if role != "stayer" {
        return Err(bad("новый участник не участвует в пересчёте"));
    }
    if !phase_is(state, group_id, "refresh").await? {
        return Ok(());
    }
    let inserted = sqlx::query(
        "INSERT INTO reshare_round1 (group_id, identifier, package) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING",
    )
    .bind(group_id)
    .bind(i32::from(identifier))
    .bind(&package)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if inserted.rows_affected() == 0 {
        return Ok(());
    }
    let others = stayer_users(state, group_id, Some(user)).await?;
    state
        .hub
        .publish_all(
            &others,
            &ServerMsg::ReshareRound1 {
                group_id,
                from: identifier,
                package,
            },
        )
        .await;
    Ok(())
}

pub async fn round2(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    packages: Vec<SealedPackage>,
) -> Result<(), ApiError> {
    let Some((from, role)) = roster_member(state, group_id, user).await? else {
        return Ok(());
    };
    if role != "stayer" {
        return Err(bad("новый участник не участвует в пересчёте"));
    }
    if !phase_is(state, group_id, "refresh").await? {
        return Ok(());
    }
    for package in packages {
        check_package(&package.ciphertext)?;
        if package.to == from {
            continue;
        }
        let Some(recipient) = user_by_identifier(state, group_id, package.to, "stayer").await?
        else {
            return Err(bad("получатель пакета не остаётся в группе"));
        };
        let inserted = sqlx::query(
            "INSERT INTO reshare_round2 (group_id, from_identifier, to_user_id, ciphertext)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(group_id)
        .bind(i32::from(from))
        .bind(recipient)
        .bind(&package.ciphertext)
        .execute(&state.pool)
        .await
        .map_err(ApiError::db)?;
        if inserted.rows_affected() == 1 {
            state
                .hub
                .publish(
                    recipient,
                    &ServerMsg::ReshareRound2 {
                        group_id,
                        from,
                        ciphertext: package.ciphertext,
                    },
                )
                .await;
        }
    }
    Ok(())
}

pub async fn refresh_public(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    package: String,
) -> Result<(), ApiError> {
    check_package(&package)?;
    let Some((identifier, role)) = roster_member(state, group_id, user).await? else {
        return Ok(());
    };
    if role != "stayer" {
        return Err(bad("новый участник не публикует пересчёт"));
    }
    let Some(phase) = phase(state, group_id).await? else {
        return Ok(());
    };
    if phase != "refresh" && phase != "repair" {
        return Ok(());
    }
    let canonical = canonical_public_package(&package).map_err(|err| bad(err.to_string()))?;
    if let Some(stored) = stored_package(
        state,
        "SELECT package FROM reshare_refresh_public WHERE group_id = $1 AND identifier = $2",
        group_id,
        identifier,
    )
    .await?
    {
        let previous = canonical_public_package(&stored).map_err(|err| bad(err.to_string()))?;
        if previous != canonical {
            return fail(state, group_id, "участники разошлись в пересчёте".into()).await;
        }
        return Ok(());
    }
    if let Some(stored) = peer_package(
        state,
        "SELECT package FROM reshare_refresh_public WHERE group_id = $1 LIMIT 1",
        group_id,
    )
    .await?
    {
        let previous = canonical_public_package(&stored).map_err(|err| bad(err.to_string()))?;
        if previous != canonical {
            return fail(state, group_id, "участники разошлись в пересчёте".into()).await;
        }
    }
    if let Err(reason) = check_group_key(state, group_id, &package, "stayer").await? {
        return fail(state, group_id, reason).await;
    }
    sqlx::query(
        "INSERT INTO reshare_refresh_public (group_id, identifier, package) VALUES ($1, $2, $3)",
    )
    .bind(group_id)
    .bind(i32::from(identifier))
    .bind(&canonical)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    finish_refresh(state, group_id).await
}

pub async fn delta(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    joiner: u16,
    packages: Vec<SealedPackage>,
) -> Result<(), ApiError> {
    let Some((from, role)) = roster_member(state, group_id, user).await? else {
        return Ok(());
    };
    if role != "stayer" {
        return Err(bad("новый участник не выдаёт дельты"));
    }
    if !phase_is(state, group_id, "repair").await? {
        return Ok(());
    }
    if user_by_identifier(state, group_id, joiner, "joiner")
        .await?
        .is_none()
    {
        return Err(bad("дельта адресована не новому участнику"));
    }
    for package in packages {
        check_package(&package.ciphertext)?;
        if package.to == from {
            continue;
        }
        let Some(recipient) = user_by_identifier(state, group_id, package.to, "stayer").await?
        else {
            return Err(bad("получатель дельты не остаётся в группе"));
        };
        let inserted = sqlx::query(
            "INSERT INTO reshare_deltas
                (group_id, joiner_identifier, from_identifier, to_user_id, ciphertext)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(group_id)
        .bind(i32::from(joiner))
        .bind(i32::from(from))
        .bind(recipient)
        .bind(&package.ciphertext)
        .execute(&state.pool)
        .await
        .map_err(ApiError::db)?;
        if inserted.rows_affected() == 1 {
            state
                .hub
                .publish(
                    recipient,
                    &ServerMsg::ReshareDelta {
                        group_id,
                        joiner,
                        from,
                        ciphertext: package.ciphertext,
                    },
                )
                .await;
        }
    }
    Ok(())
}

pub async fn sigma(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    joiner: u16,
    ciphertext: String,
    commitment: String,
) -> Result<(), ApiError> {
    check_package(&ciphertext)?;
    check_point(&commitment)?;
    let Some((from, role)) = roster_member(state, group_id, user).await? else {
        return Ok(());
    };
    if role != "stayer" {
        return Err(bad("новый участник не выдаёт сигму"));
    }
    if !phase_is(state, group_id, "repair").await? {
        return Ok(());
    }
    let Some(joiner_user) = user_by_identifier(state, group_id, joiner, "joiner").await? else {
        return Err(bad("сигма адресована не новому участнику"));
    };
    let inserted = sqlx::query(
        "INSERT INTO reshare_sigmas
            (group_id, joiner_identifier, from_identifier, ciphertext, commitment)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(group_id)
    .bind(i32::from(joiner))
    .bind(i32::from(from))
    .bind(&ciphertext)
    .bind(&commitment)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if inserted.rows_affected() == 0 {
        return Ok(());
    }
    state
        .hub
        .publish(
            joiner_user,
            &ServerMsg::ReshareSigma {
                group_id,
                joiner,
                from,
                ciphertext,
                commitment: commitment.clone(),
            },
        )
        .await;
    let others = roster_users(state, group_id, Some(user)).await?;
    state
        .hub
        .publish_all(
            &others,
            &ServerMsg::ReshareSigmaCommit {
                group_id,
                joiner,
                from,
                commitment,
            },
        )
        .await;
    Ok(())
}

pub async fn verifying(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    joiner: u16,
    verifying_share: String,
) -> Result<(), ApiError> {
    check_point(&verifying_share)?;
    let Some((identifier, role)) = roster_member(state, group_id, user).await? else {
        return Ok(());
    };
    if role != "joiner" || identifier != joiner {
        return Err(bad("долю проверки публикует новый участник"));
    }
    if !phase_is(state, group_id, "repair").await? {
        return Ok(());
    }
    let inserted = sqlx::query(
        "INSERT INTO reshare_verifyings (group_id, joiner_identifier, verifying_share)
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(group_id)
    .bind(i32::from(joiner))
    .bind(&verifying_share)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if inserted.rows_affected() == 0 {
        let stored: String = sqlx::query_scalar(
            "SELECT verifying_share FROM reshare_verifyings
             WHERE group_id = $1 AND joiner_identifier = $2",
        )
        .bind(group_id)
        .bind(i32::from(joiner))
        .fetch_one(&state.pool)
        .await
        .map_err(ApiError::db)?;
        if stored != verifying_share {
            return fail(
                state,
                group_id,
                "участники разошлись в новой доле проверки".into(),
            )
            .await;
        }
        return Ok(());
    }
    let others = roster_users(state, group_id, Some(user)).await?;
    state
        .hub
        .publish_all(
            &others,
            &ServerMsg::ReshareVerifying {
                group_id,
                joiner,
                verifying_share,
            },
        )
        .await;
    Ok(())
}

pub async fn final_public(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    package: String,
) -> Result<(), ApiError> {
    check_package(&package)?;
    let Some((identifier, _)) = roster_member(state, group_id, user).await? else {
        return Ok(());
    };
    if !phase_is(state, group_id, "repair").await? {
        return Ok(());
    }
    let canonical = canonical_public_package(&package).map_err(|err| bad(err.to_string()))?;
    if let Some(stored) = stored_package(
        state,
        "SELECT package FROM reshare_final_public WHERE group_id = $1 AND identifier = $2",
        group_id,
        identifier,
    )
    .await?
    {
        let previous = canonical_public_package(&stored).map_err(|err| bad(err.to_string()))?;
        if previous != canonical {
            return fail(
                state,
                group_id,
                "участники разошлись в публичном пакете".into(),
            )
            .await;
        }
        return Ok(());
    }
    if let Some(stored) = peer_package(
        state,
        "SELECT package FROM reshare_final_public WHERE group_id = $1 LIMIT 1",
        group_id,
    )
    .await?
    {
        let previous = canonical_public_package(&stored).map_err(|err| bad(err.to_string()))?;
        if previous != canonical {
            return fail(
                state,
                group_id,
                "участники разошлись в публичном пакете".into(),
            )
            .await;
        }
    }
    if let Err(reason) = check_group_key(state, group_id, &package, "all").await? {
        return fail(state, group_id, reason).await;
    }
    sqlx::query(
        "INSERT INTO reshare_final_public (group_id, identifier, package) VALUES ($1, $2, $3)",
    )
    .bind(group_id)
    .bind(i32::from(identifier))
    .bind(&canonical)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    finish_final(state, group_id).await
}

pub async fn abort(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    reason: String,
) -> Result<(), ApiError> {
    if roster_member(state, group_id, user).await?.is_none() {
        return Ok(());
    }
    let reason = reason.chars().take(300).collect::<String>();
    let reason = if reason.is_empty() {
        "пересчёт прерван".to_string()
    } else {
        reason
    };
    fail(state, group_id, reason).await
}

pub async fn replay(state: &AppState, user: Uuid) -> Result<Vec<ServerMsg>, ApiError> {
    let groups: Vec<Uuid> = sqlx::query_scalar(
        "SELECT s.group_id FROM reshare_sessions s
         JOIN reshare_roster r ON r.group_id = s.group_id AND r.user_id = $1
         WHERE s.phase <> 'waiting'",
    )
    .bind(user)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    let mut messages = Vec::new();
    for group_id in groups {
        let Some(session) = load_session(state, group_id).await? else {
            continue;
        };
        let Some((my_id, my_role)) = roster_member(state, group_id, user).await? else {
            continue;
        };
        messages.push(started_message(state, group_id, &session).await?);
        if my_role == "stayer" {
            let round1: Vec<(i32, String)> = sqlx::query_as(
                "SELECT identifier, package FROM reshare_round1
                 WHERE group_id = $1 AND identifier <> $2 ORDER BY identifier",
            )
            .bind(group_id)
            .bind(i32::from(my_id))
            .fetch_all(&state.pool)
            .await
            .map_err(ApiError::db)?;
            for (from, package) in round1 {
                messages.push(ServerMsg::ReshareRound1 {
                    group_id,
                    from: from as u16,
                    package,
                });
            }
            let round2: Vec<(i32, String)> = sqlx::query_as(
                "SELECT from_identifier, ciphertext FROM reshare_round2
                 WHERE group_id = $1 AND to_user_id = $2 ORDER BY from_identifier",
            )
            .bind(group_id)
            .bind(user)
            .fetch_all(&state.pool)
            .await
            .map_err(ApiError::db)?;
            for (from, ciphertext) in round2 {
                messages.push(ServerMsg::ReshareRound2 {
                    group_id,
                    from: from as u16,
                    ciphertext,
                });
            }
        }
        if session.phase != "repair" {
            continue;
        }
        if let Some(package) = session.refresh_package.clone() {
            messages.push(ServerMsg::ReshareRepair {
                group_id,
                public_key_package: package,
            });
        }
        if my_role == "stayer" {
            let deltas: Vec<(i32, i32, String)> = sqlx::query_as(
                "SELECT joiner_identifier, from_identifier, ciphertext FROM reshare_deltas
                 WHERE group_id = $1 AND to_user_id = $2
                 ORDER BY joiner_identifier, from_identifier",
            )
            .bind(group_id)
            .bind(user)
            .fetch_all(&state.pool)
            .await
            .map_err(ApiError::db)?;
            for (joiner, from, ciphertext) in deltas {
                messages.push(ServerMsg::ReshareDelta {
                    group_id,
                    joiner: joiner as u16,
                    from: from as u16,
                    ciphertext,
                });
            }
        }
        let sigmas: Vec<(i32, i32, String, String)> = sqlx::query_as(
            "SELECT joiner_identifier, from_identifier, ciphertext, commitment
             FROM reshare_sigmas WHERE group_id = $1
             ORDER BY joiner_identifier, from_identifier",
        )
        .bind(group_id)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::db)?;
        for (joiner, from, ciphertext, commitment) in sigmas {
            if my_role == "joiner" && joiner == i32::from(my_id) {
                messages.push(ServerMsg::ReshareSigma {
                    group_id,
                    joiner: joiner as u16,
                    from: from as u16,
                    ciphertext,
                    commitment: commitment.clone(),
                });
            }
            if from != i32::from(my_id) {
                messages.push(ServerMsg::ReshareSigmaCommit {
                    group_id,
                    joiner: joiner as u16,
                    from: from as u16,
                    commitment,
                });
            }
        }
        let verifyings: Vec<(i32, String)> = sqlx::query_as(
            "SELECT joiner_identifier, verifying_share FROM reshare_verifyings
             WHERE group_id = $1 ORDER BY joiner_identifier",
        )
        .bind(group_id)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::db)?;
        for (joiner, verifying_share) in verifyings {
            if joiner != i32::from(my_id) {
                messages.push(ServerMsg::ReshareVerifying {
                    group_id,
                    joiner: joiner as u16,
                    verifying_share,
                });
            }
        }
    }
    Ok(messages)
}

async fn finish_refresh(state: &AppState, group_id: Uuid) -> Result<(), ApiError> {
    let roster = load_roster(state, group_id).await?;
    let stayers: Vec<&RosterMember> = roster
        .iter()
        .filter(|member| member.role == "stayer")
        .collect();
    let joiners: Vec<&RosterMember> = roster
        .iter()
        .filter(|member| member.role == "joiner")
        .collect();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM reshare_refresh_public WHERE group_id = $1")
            .bind(group_id)
            .fetch_one(&state.pool)
            .await
            .map_err(ApiError::db)?;
    if count != stayers.len() as i64 {
        return Ok(());
    }
    let package: String = sqlx::query_scalar(
        "SELECT package FROM reshare_refresh_public WHERE group_id = $1 ORDER BY identifier LIMIT 1",
    )
    .bind(group_id)
    .fetch_one(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if joiners.is_empty() {
        return commit(state, group_id, &package, "reshare_refresh_public").await;
    }
    let updated = sqlx::query(
        "UPDATE reshare_sessions SET phase = 'repair', refresh_package = $2
         WHERE group_id = $1 AND phase = 'refresh'",
    )
    .bind(group_id)
    .bind(&package)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }
    let users = roster_users(state, group_id, None).await?;
    state
        .hub
        .publish_all(
            &users,
            &ServerMsg::ReshareRepair {
                group_id,
                public_key_package: package,
            },
        )
        .await;
    Ok(())
}

async fn finish_final(state: &AppState, group_id: Uuid) -> Result<(), ApiError> {
    let roster = load_roster(state, group_id).await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM reshare_final_public WHERE group_id = $1")
            .bind(group_id)
            .fetch_one(&state.pool)
            .await
            .map_err(ApiError::db)?;
    if count != roster.len() as i64 {
        return Ok(());
    }
    let package: String = sqlx::query_scalar(
        "SELECT package FROM reshare_final_public WHERE group_id = $1 ORDER BY identifier LIMIT 1",
    )
    .bind(group_id)
    .fetch_one(&state.pool)
    .await
    .map_err(ApiError::db)?;
    commit(state, group_id, &package, "reshare_final_public").await
}

async fn commit(
    state: &AppState,
    group_id: Uuid,
    package: &str,
    table: &str,
) -> Result<(), ApiError> {
    let mut tx = state.pool.begin().await.map_err(ApiError::db)?;
    let status: String = sqlx::query_scalar("SELECT status FROM groups WHERE id = $1 FOR UPDATE")
        .bind(group_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    if status != "resharing" {
        tx.rollback().await.ok();
        return Ok(());
    }
    let rows: Vec<String> =
        sqlx::query_scalar(&format!("SELECT package FROM {table} WHERE group_id = $1"))
            .bind(group_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(ApiError::db)?;
    let expected = canonical_public_package(package).map_err(|err| bad(err.to_string()))?;
    for row in &rows {
        let other = canonical_public_package(row).map_err(|err| bad(err.to_string()))?;
        if other != expected {
            tx.rollback().await.ok();
            return fail(
                state,
                group_id,
                "участники разошлись в публичном пакете".into(),
            )
            .await;
        }
    }
    let vk = package_verifying_key_hex(package).map_err(|err| bad(err.to_string()))?;
    let stored_vk: String =
        sqlx::query_scalar("SELECT verifying_key_hex FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::db)?;
    if vk != stored_vk {
        tx.rollback().await.ok();
        return fail(state, group_id, "пересчёт изменил ключ группы".into()).await;
    }
    let actor: String = sqlx::query_scalar(
        "SELECT u.username FROM groups g JOIN users u ON u.id = g.created_by WHERE g.id = $1",
    )
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    let leavers: Vec<String> = sqlx::query_scalar(
        "SELECT u.username FROM group_members gm
         JOIN users u ON u.id = gm.user_id
         WHERE gm.group_id = $1
           AND NOT EXISTS (
                SELECT 1 FROM reshare_roster r
                WHERE r.group_id = gm.group_id AND r.user_id = gm.user_id
           )",
    )
    .bind(group_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    let joiners: Vec<String> = sqlx::query_scalar(
        "SELECT u.username FROM reshare_roster r
         JOIN users u ON u.id = r.user_id
         WHERE r.group_id = $1 AND r.role = 'joiner'",
    )
    .bind(group_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    let roster_users: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM reshare_roster WHERE group_id = $1")
            .bind(group_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(ApiError::db)?;
    let size = i32::try_from(roster_users.len()).unwrap_or(i32::MAX);
    sqlx::query(
        "DELETE FROM group_members gm
         WHERE gm.group_id = $1
           AND NOT EXISTS (
                SELECT 1 FROM reshare_roster r
                WHERE r.group_id = gm.group_id AND r.user_id = gm.user_id
           )",
    )
    .bind(group_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    sqlx::query(
        "UPDATE groups SET status = 'active', max_signers = $2, public_key_package = $3 WHERE id = $1",
    )
    .bind(group_id)
    .bind(size)
    .bind(package)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    for subject in &leavers {
        db::insert_group_event(&mut *tx, group_id, "member_removed", &actor, subject)
            .await
            .map_err(ApiError::db)?;
    }
    for subject in &joiners {
        db::insert_group_event(&mut *tx, group_id, "member_added", &actor, subject)
            .await
            .map_err(ApiError::db)?;
    }
    delete_rows(&mut tx, group_id).await?;
    tx.commit().await.map_err(ApiError::db)?;
    state
        .hub
        .publish_all(
            &roster_users,
            &ServerMsg::ReshareCompleted {
                group_id,
                verifying_key_hex: vk,
            },
        )
        .await;
    publish_group(state, group_id).await
}

async fn fail(state: &AppState, group_id: Uuid, reason: String) -> Result<(), ApiError> {
    let mut tx = state.pool.begin().await.map_err(ApiError::db)?;
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM groups WHERE id = $1 FOR UPDATE")
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::db)?;
    if status.as_deref() != Some("resharing") {
        tx.rollback().await.ok();
        return Ok(());
    }
    let users: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM reshare_roster WHERE group_id = $1")
            .bind(group_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(ApiError::db)?;
    sqlx::query(
        "DELETE FROM group_members gm
         WHERE gm.group_id = $1
           AND EXISTS (
                SELECT 1 FROM reshare_roster r
                WHERE r.group_id = gm.group_id AND r.user_id = gm.user_id AND r.role = 'joiner'
           )",
    )
    .bind(group_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    sqlx::query("UPDATE groups SET status = 'active' WHERE id = $1")
        .bind(group_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    delete_rows(&mut tx, group_id).await?;
    tx.commit().await.map_err(ApiError::db)?;
    state
        .hub
        .publish_all(
            &users,
            &ServerMsg::ReshareFailed {
                group_id,
                message: reason,
            },
        )
        .await;
    publish_group(state, group_id).await
}

async fn delete_rows(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group_id: Uuid,
) -> Result<(), ApiError> {
    for table in [
        "reshare_round1",
        "reshare_round2",
        "reshare_refresh_public",
        "reshare_deltas",
        "reshare_sigmas",
        "reshare_verifyings",
        "reshare_final_public",
        "reshare_roster",
        "reshare_sessions",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE group_id = $1"))
            .bind(group_id)
            .execute(&mut **tx)
            .await
            .map_err(ApiError::db)?;
    }
    Ok(())
}

async fn publish_started(state: &AppState, group_id: Uuid) -> Result<(), ApiError> {
    let Some(session) = load_session(state, group_id).await? else {
        return Ok(());
    };
    let message = started_message(state, group_id, &session).await?;
    let users = roster_users(state, group_id, None).await?;
    state.hub.publish_all(&users, &message).await;
    Ok(())
}

async fn started_message(
    state: &AppState,
    group_id: Uuid,
    session: &SessionRow,
) -> Result<ServerMsg, ApiError> {
    let roster = load_roster(state, group_id).await?;
    let mut stayers = Vec::new();
    let mut joiners = Vec::new();
    let mut keys = Vec::new();
    for member in roster {
        let identifier = member.identifier as u16;
        let Some(box_public_hex) = member.box_public else {
            return Err(bad("у участника пересчёта нет ключа группы"));
        };
        if member.role == "joiner" {
            joiners.push(identifier);
        } else {
            stayers.push(identifier);
        }
        keys.push(RosterKey {
            identifier,
            box_public_hex,
        });
    }
    Ok(ServerMsg::ReshareStarted {
        group_id,
        generation: session.generation as u32,
        threshold: session.threshold as u16,
        stayers,
        joiners,
        keys,
    })
}

async fn check_group_key(
    state: &AppState,
    group_id: Uuid,
    package: &str,
    who: &str,
) -> Result<Result<(), String>, ApiError> {
    let vk = package_verifying_key_hex(package).map_err(|err| bad(err.to_string()))?;
    let stored: Option<String> =
        sqlx::query_scalar("SELECT verifying_key_hex FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::db)?;
    if stored.as_deref() != Some(vk.as_str()) {
        return Ok(Err("пересчёт изменил ключ группы".into()));
    }
    let ids = package_signer_ids(package).map_err(|err| bad(err.to_string()))?;
    let roster = load_roster(state, group_id).await?;
    let mut expected: Vec<u16> = roster
        .iter()
        .filter(|member| who == "all" || member.role == who)
        .map(|member| member.identifier as u16)
        .collect();
    expected.sort_unstable();
    if ids != expected {
        return Ok(Err("публичный пакет не совпал с составом".into()));
    }
    Ok(Ok(()))
}

fn names(values: &[String]) -> Result<Vec<String>, ApiError> {
    let mut seen = std::collections::HashSet::new();
    let mut names = Vec::new();
    for value in values {
        let name = value.trim();
        if name.is_empty() {
            return Err(bad("укажите имя участника"));
        }
        if !seen.insert(name.to_string()) {
            return Err(bad(format!("участник {name} указан дважды")));
        }
        names.push(name.to_string());
    }
    Ok(names)
}

async fn active_signer(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    username: &str,
) -> Result<Uuid, ApiError> {
    let row: Option<(Uuid, String, Option<String>)> =
        sqlx::query_as("SELECT id, role, box_public FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(executor)
            .await
            .map_err(ApiError::db)?;
    let Some((id, role, box_public)) = row else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("пользователь {username} не найден"),
        ));
    };
    if role != ai_signing_protocol::ROLE_SIGNER {
        return Err(bad(format!("{username} не подписант")));
    }
    if box_public.is_none() {
        return Err(bad(format!(
            "у {username} ещё нет ключа устройства: пусть этот пользователь откроет клиент"
        )));
    }
    Ok(id)
}

async fn load_session(state: &AppState, group_id: Uuid) -> Result<Option<SessionRow>, ApiError> {
    sqlx::query_as(
        "SELECT generation, phase, threshold, refresh_package FROM reshare_sessions WHERE group_id = $1",
    )
    .bind(group_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)
}

async fn load_roster(state: &AppState, group_id: Uuid) -> Result<Vec<RosterMember>, ApiError> {
    sqlx::query_as(
        "SELECT r.identifier, r.role, gm.box_public
         FROM reshare_roster r
         JOIN group_members gm ON gm.group_id = r.group_id AND gm.user_id = r.user_id
         WHERE r.group_id = $1
         ORDER BY r.identifier",
    )
    .bind(group_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)
}

async fn roster_member(
    state: &AppState,
    group_id: Uuid,
    user: Uuid,
) -> Result<Option<(u16, String)>, ApiError> {
    let row: Option<(i32, String)> = sqlx::query_as(
        "SELECT identifier, role FROM reshare_roster WHERE group_id = $1 AND user_id = $2",
    )
    .bind(group_id)
    .bind(user)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(row.map(|(identifier, role)| (identifier as u16, role)))
}

async fn phase(state: &AppState, group_id: Uuid) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar("SELECT phase FROM reshare_sessions WHERE group_id = $1")
        .bind(group_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::db)
}

async fn phase_is(state: &AppState, group_id: Uuid, expected: &str) -> Result<bool, ApiError> {
    Ok(phase(state, group_id).await?.as_deref() == Some(expected))
}

async fn user_by_identifier(
    state: &AppState,
    group_id: Uuid,
    identifier: u16,
    role: &str,
) -> Result<Option<Uuid>, ApiError> {
    sqlx::query_scalar(
        "SELECT user_id FROM reshare_roster
         WHERE group_id = $1 AND identifier = $2 AND role = $3",
    )
    .bind(group_id)
    .bind(i32::from(identifier))
    .bind(role)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)
}

async fn roster_users(
    state: &AppState,
    group_id: Uuid,
    except: Option<Uuid>,
) -> Result<Vec<Uuid>, ApiError> {
    let users: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM reshare_roster WHERE group_id = $1")
            .bind(group_id)
            .fetch_all(&state.pool)
            .await
            .map_err(ApiError::db)?;
    Ok(users
        .into_iter()
        .filter(|user| Some(*user) != except)
        .collect())
}

async fn stayer_users(
    state: &AppState,
    group_id: Uuid,
    except: Option<Uuid>,
) -> Result<Vec<Uuid>, ApiError> {
    let users: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM reshare_roster WHERE group_id = $1 AND role = 'stayer'",
    )
    .bind(group_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(users
        .into_iter()
        .filter(|user| Some(*user) != except)
        .collect())
}

async fn peer_package(
    state: &AppState,
    sql: &str,
    group_id: Uuid,
) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar(sql)
        .bind(group_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::db)
}

async fn stored_package(
    state: &AppState,
    sql: &str,
    group_id: Uuid,
    identifier: u16,
) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar(sql)
        .bind(group_id)
        .bind(i32::from(identifier))
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::db)
}

fn check_point(value: &str) -> Result<(), ApiError> {
    let bytes = hex::decode(value.trim()).map_err(|_| bad("точка не является hex"))?;
    if bytes.len() != 32 {
        return Err(bad("точка должна быть 32 байта"));
    }
    Ok(())
}
