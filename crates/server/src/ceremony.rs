use ai_signing_protocol::{
    aggregate_signature, package_verifying_key_hex, ServerMsg, SignRequestDto,
};
use axum::http::StatusCode;
use uuid::Uuid;

use crate::{
    db::{self, check_package},
    error::{bad, ApiError},
    AppState,
};

pub async fn publish_group(state: &AppState, group_id: Uuid) -> Result<(), ApiError> {
    let users = db::audience(&state.pool, group_id)
        .await
        .map_err(ApiError::db)?;
    for user in users {
        let group = db::load_group(&state.pool, group_id, user)
            .await
            .map_err(ApiError::db)?;
        state
            .hub
            .publish(user, &ServerMsg::GroupUpdated { group })
            .await;
    }
    Ok(())
}

async fn publish_sign_completed(
    state: &AppState,
    group_id: Uuid,
    request_id: Uuid,
    signature: &str,
) -> Result<(), ApiError> {
    let creator: Option<Uuid> = sqlx::query_scalar("SELECT created_by FROM groups WHERE id = $1")
        .bind(group_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::db)?;
    let users = db::audience(&state.pool, group_id)
        .await
        .map_err(ApiError::db)?;
    for user in users {
        let signature_hex = if Some(user) == creator {
            signature.to_string()
        } else {
            String::new()
        };
        state
            .hub
            .publish(
                user,
                &ServerMsg::SignCompleted {
                    request_id,
                    signature_hex,
                },
            )
            .await;
    }
    Ok(())
}

async fn publish_request(
    state: &AppState,
    request_id: Uuid,
    group_id: Uuid,
) -> Result<(), ApiError> {
    // Создатель группы не участник, но видит запросы, которые отправил.
    let users = db::audience(&state.pool, group_id)
        .await
        .map_err(ApiError::db)?;
    for user in users {
        let request = db::load_request(&state.pool, request_id, user, false)
            .await
            .map_err(ApiError::db)?;
        state
            .hub
            .publish(user, &ServerMsg::SignRequest { request })
            .await;
    }
    Ok(())
}

pub async fn start_dkg(state: &AppState, user: Uuid, group_id: Uuid) -> Result<(), ApiError> {
    let group = db::load_group(&state.pool, group_id, user)
        .await
        .map_err(ApiError::db)?;
    if !group.i_created {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "запустить DKG может создатель группы",
        ));
    }
    if group.status != "forming" {
        return Err(bad("группа уже не набирает участников"));
    }
    if group.members.len() != usize::from(group.max_signers) {
        return Err(bad(format!(
            "нужно {} участников, сейчас {}",
            group.max_signers,
            group.members.len()
        )));
    }
    if let Some(member) = group
        .members
        .iter()
        .find(|member| member.box_public_hex.is_none())
    {
        return Err(bad(format!(
            "у {} ещё нет ключа для этой группы: пусть этот пользователь откроет приложение",
            member.username
        )));
    }
    let updated =
        sqlx::query("UPDATE groups SET status = 'dkg' WHERE id = $1 AND status = 'forming'")
            .bind(group_id)
            .execute(&state.pool)
            .await
            .map_err(ApiError::db)?;
    if updated.rows_affected() == 0 {
        return Err(bad("не удалось начать DKG"));
    }
    publish_group(state, group_id).await?;
    let members = db::member_ids(&state.pool, group_id)
        .await
        .map_err(ApiError::db)?;
    state
        .hub
        .publish_all(&members, &ServerMsg::DkgStarted { group_id })
        .await;
    Ok(())
}

pub async fn dkg_round1(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    package: String,
) -> Result<(), ApiError> {
    check_package(&package)?;
    ensure_status(state, group_id, "dkg").await?;
    let identifier = db::require_member(&state.pool, group_id, user).await?;
    let inserted = sqlx::query(
        "INSERT INTO dkg_round1 (group_id, identifier, package) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
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
    let others: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM group_members WHERE group_id = $1 AND user_id <> $2",
    )
    .bind(group_id)
    .bind(user)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    state
        .hub
        .publish_all(
            &others,
            &ServerMsg::DkgRound1 {
                group_id,
                from: identifier,
                package,
            },
        )
        .await;
    Ok(())
}

pub async fn dkg_round2(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    packages: Vec<ai_signing_protocol::SealedPackage>,
) -> Result<(), ApiError> {
    ensure_status(state, group_id, "dkg").await?;
    let from = db::require_member(&state.pool, group_id, user).await?;
    for package in packages {
        check_package(&package.ciphertext)?;
        if package.to == from {
            continue;
        }
        let recipient: Option<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM group_members WHERE group_id = $1 AND identifier = $2",
        )
        .bind(group_id)
        .bind(i32::from(package.to))
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::db)?;
        let Some(recipient) = recipient else {
            return Err(bad("получатель пакета не состоит в группе"));
        };
        let inserted = sqlx::query(
            "INSERT INTO dkg_round2 (group_id, from_identifier, to_user_id, ciphertext)
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
                    &ServerMsg::DkgRound2 {
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

pub async fn dkg_public(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    package: String,
) -> Result<(), ApiError> {
    check_package(&package)?;
    let _ = package_verifying_key_hex(&package).map_err(|err| bad(err.to_string()))?;
    ensure_status(state, group_id, "dkg").await?;
    let identifier = db::require_member(&state.pool, group_id, user).await?;
    sqlx::query(
        "INSERT INTO dkg_publics (group_id, identifier, package) VALUES ($1, $2, $3)
         ON CONFLICT (group_id, identifier) DO NOTHING",
    )
    .bind(group_id)
    .bind(i32::from(identifier))
    .bind(&package)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    finish_dkg(state, group_id).await
}

pub async fn dkg_abort(
    state: &AppState,
    user: Uuid,
    group_id: Uuid,
    reason: String,
) -> Result<(), ApiError> {
    db::require_member(&state.pool, group_id, user).await?;
    fail_dkg(state, group_id, reason).await
}

async fn finish_dkg(state: &AppState, group_id: Uuid) -> Result<(), ApiError> {
    let mut tx = state.pool.begin().await.map_err(ApiError::db)?;
    let status: String = sqlx::query_scalar("SELECT status FROM groups WHERE id = $1 FOR UPDATE")
        .bind(group_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    if status != "dkg" {
        tx.rollback().await.ok();
        return Ok(());
    }
    let max_signers: i32 = sqlx::query_scalar("SELECT max_signers FROM groups WHERE id = $1")
        .bind(group_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    let packages: Vec<(i32, String)> = sqlx::query_as(
        "SELECT identifier, package FROM dkg_publics WHERE group_id = $1 ORDER BY identifier",
    )
    .bind(group_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    if packages.len() != max_signers as usize {
        tx.commit().await.map_err(ApiError::db)?;
        return Ok(());
    }
    let vk = package_verifying_key_hex(&packages[0].1).map_err(|err| bad(err.to_string()))?;
    for (_, package) in packages.iter().skip(1) {
        let other = package_verifying_key_hex(package).map_err(|err| bad(err.to_string()))?;
        if other != vk {
            sqlx::query("UPDATE groups SET status = 'failed' WHERE id = $1")
                .bind(group_id)
                .execute(&mut *tx)
                .await
                .map_err(ApiError::db)?;
            tx.commit().await.map_err(ApiError::db)?;
            let members = db::member_ids(&state.pool, group_id)
                .await
                .map_err(ApiError::db)?;
            state
                .hub
                .publish_all(
                    &members,
                    &ServerMsg::DkgFailed {
                        group_id,
                        message: "участники получили разные ключи группы".into(),
                    },
                )
                .await;
            publish_group(state, group_id).await?;
            return Ok(());
        }
    }
    sqlx::query(
        "UPDATE groups SET status = 'active', verifying_key_hex = $2, public_key_package = $3 WHERE id = $1",
    )
    .bind(group_id)
    .bind(&vk)
    .bind(&packages[0].1)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    tx.commit().await.map_err(ApiError::db)?;
    let members = db::member_ids(&state.pool, group_id)
        .await
        .map_err(ApiError::db)?;
    state
        .hub
        .publish_all(
            &members,
            &ServerMsg::DkgCompleted {
                group_id,
                verifying_key_hex: vk,
            },
        )
        .await;
    publish_group(state, group_id).await?;
    Ok(())
}

async fn fail_dkg(state: &AppState, group_id: Uuid, reason: String) -> Result<(), ApiError> {
    let updated =
        sqlx::query("UPDATE groups SET status = 'failed' WHERE id = $1 AND status = 'dkg'")
            .bind(group_id)
            .execute(&state.pool)
            .await
            .map_err(ApiError::db)?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }
    let members = db::member_ids(&state.pool, group_id)
        .await
        .map_err(ApiError::db)?;
    state
        .hub
        .publish_all(
            &members,
            &ServerMsg::DkgFailed {
                group_id,
                message: reason,
            },
        )
        .await;
    publish_group(state, group_id).await
}

pub async fn create_request(
    state: &AppState,
    group_id: Uuid,
    message: Vec<u8>,
) -> Result<SignRequestDto, ApiError> {
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM groups WHERE id = $1")
        .bind(group_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::db)?;
    let Some(status) = status else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "группа не найдена"));
    };
    if status != "active" {
        return Err(bad("группа ещё не готова подписывать"));
    }
    let request_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO signing_requests (id, group_id, message, status) VALUES ($1, $2, $3, 'pending')",
    )
    .bind(request_id)
    .bind(group_id)
    .bind(&message)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    publish_request(state, request_id, group_id).await?;
    db::load_request(&state.pool, request_id, Uuid::nil(), false)
        .await
        .map_err(ApiError::db)
}

pub async fn decide(
    state: &AppState,
    user: Uuid,
    request_id: Uuid,
    approved: bool,
) -> Result<(), ApiError> {
    let mut tx = state.pool.begin().await.map_err(ApiError::db)?;
    let locked: Option<(Uuid, String, Vec<u8>, i32)> = sqlx::query_as(
        "SELECT r.group_id, r.status, r.message, g.threshold
         FROM signing_requests r
         JOIN groups g ON g.id = r.group_id
         WHERE r.id = $1
         FOR UPDATE OF r",
    )
    .bind(request_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    let Some((group_id, status, message, threshold)) = locked else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "запрос не найден"));
    };
    let identifier = db::require_member(&state.pool, group_id, user).await?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT decision FROM signing_approvals WHERE request_id = $1 AND user_id = $2",
    )
    .bind(request_id)
    .bind(user)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    if let Some(previous) = existing {
        tx.rollback().await.ok();
        let same = if approved {
            previous == "approved"
        } else {
            previous == "rejected"
        };
        return if same {
            Ok(())
        } else {
            Err(bad("решение уже принято"))
        };
    }
    if status != "pending" {
        tx.rollback().await.ok();
        return Err(bad("запрос уже не принимает решения"));
    }
    let decision = if approved { "approved" } else { "rejected" };
    sqlx::query(
        "INSERT INTO signing_approvals (request_id, user_id, decision) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING",
    )
    .bind(request_id)
    .bind(user)
    .bind(decision)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::db)?;

    let rejected: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM signing_approvals WHERE request_id = $1 AND decision = 'rejected'",
    )
    .bind(request_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    let members: i64 = sqlx::query_scalar("SELECT count(*) FROM group_members WHERE group_id = $1")
        .bind(group_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    let approvals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM signing_approvals WHERE request_id = $1 AND decision = 'approved'",
    )
    .bind(request_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::db)?;

    let mut started: Vec<(Uuid, u16)> = Vec::new();
    if members - rejected < i64::from(threshold) {
        sqlx::query(
            "UPDATE signing_requests SET status = 'failed', error = $2, completed_at = now() WHERE id = $1",
        )
        .bind(request_id)
        .bind("кворум недостижим")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::db)?;
        tx.commit().await.map_err(ApiError::db)?;
        publish_request(state, request_id, group_id).await?;
        let users = db::audience(&state.pool, group_id)
            .await
            .map_err(ApiError::db)?;
        state
            .hub
            .publish_all(
                &users,
                &ServerMsg::SignFailed {
                    request_id,
                    message: "кворум недостижим".into(),
                },
            )
            .await;
        return Ok(());
    }

    if approvals >= i64::from(threshold) {
        let signers: Vec<(Uuid, i32)> = sqlx::query_as(
            "SELECT gm.user_id, gm.identifier
             FROM signing_approvals a
             JOIN group_members gm ON gm.user_id = a.user_id AND gm.group_id = $2
             WHERE a.request_id = $1 AND a.decision = 'approved'
             ORDER BY gm.identifier
             LIMIT $3",
        )
        .bind(request_id)
        .bind(group_id)
        .bind(threshold)
        .fetch_all(&mut *tx)
        .await
        .map_err(ApiError::db)?;
        sqlx::query(
            "UPDATE signing_requests SET status = 'signing' WHERE id = $1 AND status = 'pending'",
        )
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::db)?;
        for (signer, ident) in &signers {
            sqlx::query(
                "INSERT INTO sign_participants (request_id, user_id, identifier) VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING",
            )
            .bind(request_id)
            .bind(signer)
            .bind(ident)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::db)?;
            started.push((*signer, *ident as u16));
        }
        let _ = identifier;
        let signer_ids: Vec<u16> = started.iter().map(|(_, ident)| *ident).collect();
        tx.commit().await.map_err(ApiError::db)?;
        publish_request(state, request_id, group_id).await?;
        let message_hex = hex::encode(message);
        for (signer, _) in &started {
            state
                .hub
                .publish(
                    *signer,
                    &ServerMsg::SignStarted {
                        request_id,
                        group_id,
                        signers: signer_ids.clone(),
                        message_hex: message_hex.clone(),
                    },
                )
                .await;
        }
        return Ok(());
    }

    tx.commit().await.map_err(ApiError::db)?;
    publish_request(state, request_id, group_id).await
}

pub async fn sign_commitment(
    state: &AppState,
    user: Uuid,
    request_id: Uuid,
    commitment: String,
) -> Result<(), ApiError> {
    check_package(&commitment)?;
    let participant = signing_participant(state, request_id, user).await?;
    let Some((group_id, identifier)) = participant else {
        return Err(bad("вы не входите в комитет этой подписи"));
    };
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT commitment FROM sign_commitments WHERE request_id = $1 AND identifier = $2",
    )
    .bind(request_id)
    .bind(i32::from(identifier))
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if let Some(existing) = existing {
        if existing != commitment {
            fail_sign(
                state,
                request_id,
                group_id,
                "участник прислал другое обязательство".into(),
            )
            .await?;
        }
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO sign_commitments (request_id, identifier, commitment) VALUES ($1, $2, $3)",
    )
    .bind(request_id)
    .bind(i32::from(identifier))
    .bind(&commitment)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    let signers = signer_users(state, request_id).await?;
    state
        .hub
        .publish_all(
            &signers,
            &ServerMsg::SignCommitment {
                request_id,
                from: identifier,
                commitment,
            },
        )
        .await;
    Ok(())
}

pub async fn sign_share(
    state: &AppState,
    user: Uuid,
    request_id: Uuid,
    share: String,
) -> Result<(), ApiError> {
    check_package(&share)?;
    let Some((group_id, identifier)) = signing_participant(state, request_id, user).await? else {
        return Err(bad("вы не входите в комитет этой подписи"));
    };
    let mut tx = state.pool.begin().await.map_err(ApiError::db)?;
    let status: String =
        sqlx::query_scalar("SELECT status FROM signing_requests WHERE id = $1 FOR UPDATE")
            .bind(request_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::db)?;
    if status != "signing" {
        tx.rollback().await.ok();
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO sign_shares (request_id, identifier, share) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(request_id)
    .bind(i32::from(identifier))
    .bind(&share)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    let have: i64 = sqlx::query_scalar("SELECT count(*) FROM sign_shares WHERE request_id = $1")
        .bind(request_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    let need: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sign_participants WHERE request_id = $1")
            .bind(request_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::db)?;
    if have < need {
        tx.commit().await.map_err(ApiError::db)?;
        return Ok(());
    }
    let message: Vec<u8> = sqlx::query_scalar("SELECT message FROM signing_requests WHERE id = $1")
        .bind(request_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::db)?;
    let commitments: Vec<(i32, String)> =
        sqlx::query_as("SELECT identifier, commitment FROM sign_commitments WHERE request_id = $1 ORDER BY identifier")
            .bind(request_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(ApiError::db)?;
    let shares: Vec<(i32, String)> = sqlx::query_as(
        "SELECT identifier, share FROM sign_shares WHERE request_id = $1 ORDER BY identifier",
    )
    .bind(request_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(ApiError::db)?;
    let pubkey: Option<String> =
        sqlx::query_scalar("SELECT public_key_package FROM groups WHERE id = $1")
            .bind(group_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::db)?;
    let Some(pubkey) = pubkey else {
        tx.rollback().await.ok();
        return Err(bad("у группы нет публичного ключа"));
    };
    let commitments: Vec<(u16, String)> = commitments
        .into_iter()
        .map(|(id, value)| (id as u16, value))
        .collect();
    let shares: Vec<(u16, String)> = shares
        .into_iter()
        .map(|(id, value)| (id as u16, value))
        .collect();
    match aggregate_signature(&message, &commitments, &shares, &pubkey) {
        Ok(signature) => {
            sqlx::query(
                "UPDATE signing_requests
                 SET status = 'completed', signature_hex = $2, completed_at = now()
                 WHERE id = $1",
            )
            .bind(request_id)
            .bind(&signature)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::db)?;
            tx.commit().await.map_err(ApiError::db)?;
            publish_request(state, request_id, group_id).await?;
            publish_sign_completed(state, group_id, request_id, &signature).await?;
            Ok(())
        }
        Err(err) => {
            tx.rollback().await.ok();
            fail_sign(state, request_id, group_id, err.to_string()).await
        }
    }
}

pub async fn sign_abort(
    state: &AppState,
    user: Uuid,
    request_id: Uuid,
    reason: String,
) -> Result<(), ApiError> {
    let Some((group_id, _)) = signing_participant(state, request_id, user).await? else {
        return Err(bad("вы не входите в комитет этой подписи"));
    };
    fail_sign(state, request_id, group_id, reason).await
}

async fn fail_sign(
    state: &AppState,
    request_id: Uuid,
    group_id: Uuid,
    reason: String,
) -> Result<(), ApiError> {
    let updated = sqlx::query(
        "UPDATE signing_requests SET status = 'failed', error = $2, completed_at = now()
         WHERE id = $1 AND status = 'signing'",
    )
    .bind(request_id)
    .bind(&reason)
    .execute(&state.pool)
    .await
    .map_err(ApiError::db)?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }
    publish_request(state, request_id, group_id).await?;
    let users = db::audience(&state.pool, group_id)
        .await
        .map_err(ApiError::db)?;
    state
        .hub
        .publish_all(
            &users,
            &ServerMsg::SignFailed {
                request_id,
                message: reason,
            },
        )
        .await;
    Ok(())
}

async fn ensure_status(state: &AppState, group_id: Uuid, expected: &str) -> Result<(), ApiError> {
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM groups WHERE id = $1")
        .bind(group_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::db)?;
    match status {
        Some(status) if status == expected => Ok(()),
        Some(_) => Err(bad("группа не в той фазе")),
        None => Err(ApiError::new(StatusCode::NOT_FOUND, "группа не найдена")),
    }
}

async fn signing_participant(
    state: &AppState,
    request_id: Uuid,
    user: Uuid,
) -> Result<Option<(Uuid, u16)>, ApiError> {
    let row: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT r.group_id, p.identifier
         FROM sign_participants p
         JOIN signing_requests r ON r.id = p.request_id
         WHERE p.request_id = $1 AND p.user_id = $2 AND r.status = 'signing'",
    )
    .bind(request_id)
    .bind(user)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::db)?;
    Ok(row.map(|(group_id, identifier)| (group_id, identifier as u16)))
}

async fn signer_users(state: &AppState, request_id: Uuid) -> Result<Vec<Uuid>, ApiError> {
    sqlx::query_scalar("SELECT user_id FROM sign_participants WHERE request_id = $1")
        .bind(request_id)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::db)
}

pub async fn replay(state: &AppState, user: Uuid) -> Result<Vec<ServerMsg>, ApiError> {
    let mut messages = Vec::new();
    let groups: Vec<Uuid> = sqlx::query_scalar(
        "SELECT g.id FROM groups g
         JOIN group_members m ON m.group_id = g.id
         WHERE m.user_id = $1 AND g.status = 'dkg'",
    )
    .bind(user)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    for group_id in groups {
        let my_ident: i32 = sqlx::query_scalar(
            "SELECT identifier FROM group_members WHERE group_id = $1 AND user_id = $2",
        )
        .bind(group_id)
        .bind(user)
        .fetch_one(&state.pool)
        .await
        .map_err(ApiError::db)?;
        messages.push(ServerMsg::DkgStarted { group_id });
        let round1: Vec<(i32, String)> = sqlx::query_as(
            "SELECT identifier, package FROM dkg_round1 WHERE group_id = $1 AND identifier <> $2 ORDER BY identifier",
        )
        .bind(group_id)
        .bind(my_ident)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::db)?;
        for (from, package) in round1 {
            messages.push(ServerMsg::DkgRound1 {
                group_id,
                from: from as u16,
                package,
            });
        }
        let round2: Vec<(i32, String)> = sqlx::query_as(
            "SELECT from_identifier, ciphertext FROM dkg_round2
             WHERE group_id = $1 AND to_user_id = $2 ORDER BY from_identifier",
        )
        .bind(group_id)
        .bind(user)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::db)?;
        for (from, ciphertext) in round2 {
            messages.push(ServerMsg::DkgRound2 {
                group_id,
                from: from as u16,
                ciphertext,
            });
        }
    }

    let requests: Vec<(Uuid, Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT r.id, r.group_id, r.message
         FROM signing_requests r
         JOIN sign_participants p ON p.request_id = r.id AND p.user_id = $1
         WHERE r.status = 'signing'",
    )
    .bind(user)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::db)?;
    for (request_id, group_id, message) in requests {
        let signers: Vec<i32> = sqlx::query_scalar(
            "SELECT identifier FROM sign_participants WHERE request_id = $1 ORDER BY identifier",
        )
        .bind(request_id)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::db)?;
        messages.push(ServerMsg::SignStarted {
            request_id,
            group_id,
            signers: signers.iter().map(|id| *id as u16).collect(),
            message_hex: hex::encode(message),
        });
        let commitments: Vec<(i32, String)> = sqlx::query_as(
            "SELECT identifier, commitment FROM sign_commitments WHERE request_id = $1 ORDER BY identifier",
        )
        .bind(request_id)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::db)?;
        for (from, commitment) in commitments {
            messages.push(ServerMsg::SignCommitment {
                request_id,
                from: from as u16,
                commitment,
            });
        }
    }
    Ok(messages)
}
