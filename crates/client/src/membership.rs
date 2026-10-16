use std::collections::HashSet;

use ai_signing_protocol::{GroupDto, SignRequestDto, MAX_SIGNERS};
use uuid::Uuid;

pub fn signing_in_progress(group_id: Uuid, requests: &[SignRequestDto]) -> bool {
    requests.iter().any(|request| {
        request.group_id == group_id
            && matches!(request.status.as_str(), "pending" | "signing")
    })
}

/// Checks a membership change before the client asks the server to reshare.
/// The returned names are trimmed. The threshold and the group key stay as they are.
pub fn membership_change(
    group: &GroupDto,
    requests: &[SignRequestDto],
    add: &[String],
    remove: &[String],
) -> Result<(Vec<String>, Vec<String>), String> {
    if !group.i_created {
        return Err("Пересчитывать доли может создатель группы".into());
    }
    if signing_in_progress(group.id, requests) {
        return Err("Дождитесь завершения текущей подписи".into());
    }
    if group.status != "active" {
        return Err(match group.status.as_str() {
            "resharing" => "Дождитесь завершения текущего пересчёта долей".into(),
            "dkg" => "Дождитесь завершения генерации ключа".into(),
            _ => "Пересчёт долей доступен только активной группе".into(),
        });
    }
    let add = clean_names(add)?;
    let remove = clean_names(remove)?;
    if add.is_empty() && remove.is_empty() {
        return Err("Укажите, кого добавить или удалить".into());
    }
    if add
        .iter()
        .any(|name| remove.iter().any(|other| other == name))
    {
        return Err("Нельзя одновременно добавить и удалить одного участника".into());
    }
    for name in &remove {
        if !group.members.iter().any(|member| &member.username == name) {
            return Err(format!("Пользователь {name} не в группе"));
        }
    }
    for name in &add {
        if group.members.iter().any(|member| &member.username == name) {
            return Err(format!("Пользователь {name} уже в группе"));
        }
    }
    let stayers: Vec<_> = group
        .members
        .iter()
        .filter(|member| !remove.iter().any(|name| name == &member.username))
        .collect();
    if stayers.len() < 2 || stayers.len() < usize::from(group.threshold) {
        return Err("После удаления участников порог должен выполняться".into());
    }
    if stayers.len() + add.len() > usize::from(MAX_SIGNERS) {
        return Err(format!("В группе не больше {MAX_SIGNERS} участников"));
    }
    for member in &stayers {
        if member.box_public_hex.is_none() {
            return Err(format!(
                "У {} ещё нет ключа для этой группы: пусть этот пользователь откроет приложение",
                member.username
            ));
        }
    }
    let mut next = group
        .members
        .iter()
        .map(|member| member.identifier)
        .max()
        .unwrap_or(0);
    for _ in &add {
        next = next
            .checked_add(1)
            .ok_or_else(|| "Закончились идентификаторы участников".to_string())?;
    }
    Ok((add, remove))
}

fn clean_names(values: &[String]) -> Result<Vec<String>, String> {
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for value in values {
        let name = value.trim();
        if name.is_empty() {
            return Err("Укажите имя участника".into());
        }
        if !seen.insert(name.to_string()) {
            return Err(format!("Участник {name} указан дважды"));
        }
        names.push(name.to_string());
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::membership_change;
    use ai_signing_protocol::{GroupDto, MemberDto, MAX_SIGNERS};
    use uuid::Uuid;

    fn member(name: &str, identifier: u16, key: bool) -> MemberDto {
        MemberDto {
            user_id: Uuid::from_u128(u128::from(identifier)),
            username: name.into(),
            identifier,
            box_public_hex: key.then(|| "aa".into()),
            participation_accepted: key,
        }
    }

    fn active_group(threshold: u16, members: Vec<MemberDto>) -> GroupDto {
        GroupDto {
            id: Uuid::nil(),
            name: "treasury".into(),
            threshold,
            max_signers: u16::try_from(members.len()).unwrap_or(MAX_SIGNERS),
            status: "active".into(),
            api_token: None,
            verifying_key_hex: None,
            solana_address: None,
            created_by: Uuid::nil(),
            i_created: true,
            my_identifier: None,
            members,
        }
    }

    #[test]
    fn add_and_remove_keep_the_threshold() {
        let group = active_group(
            2,
            vec![
                member("alice", 1, true),
                member("bob", 2, true),
                member("carol", 3, true),
            ],
        );
        let (add, remove) =
            membership_change(&group, &[], &[" dave ".into()], &["carol".into()]).unwrap();
        assert_eq!(add, vec!["dave".to_string()]);
        assert_eq!(remove, vec!["carol".to_string()]);
    }

    #[test]
    fn rejects_a_change_that_breaks_the_group() {
        let mut group = active_group(2, vec![member("alice", 1, true), member("bob", 2, false)]);
        assert_eq!(
            membership_change(&group, &[], &[], &[]).unwrap_err(),
            "Укажите, кого добавить или удалить"
        );
        assert_eq!(
            membership_change(&group, &[], &["alice".into()], &["alice".into()]).unwrap_err(),
            "Нельзя одновременно добавить и удалить одного участника"
        );
        assert_eq!(
            membership_change(&group, &[], &[], &["carol".into()]).unwrap_err(),
            "Пользователь carol не в группе"
        );
        assert_eq!(
            membership_change(&group, &[], &["bob".into()], &[]).unwrap_err(),
            "Пользователь bob уже в группе"
        );
        assert_eq!(
            membership_change(&group, &[], &[], &["alice".into()]).unwrap_err(),
            "После удаления участников порог должен выполняться"
        );
        assert_eq!(
            membership_change(&group, &[], &["carol".into()], &[]).unwrap_err(),
            "У bob ещё нет ключа для этой группы: пусть этот пользователь откроет приложение"
        );
        assert_eq!(
            membership_change(&group, &[], &["carol".into(), "carol".into()], &["bob".into()])
                .unwrap_err(),
            "Участник carol указан дважды"
        );
        assert_eq!(
            membership_change(&group, &[], &[" ".into()], &[]).unwrap_err(),
            "Укажите имя участника"
        );
        group.i_created = false;
        assert_eq!(
            membership_change(&group, &[], &["carol".into()], &[]).unwrap_err(),
            "Пересчитывать доли может создатель группы"
        );
        group.i_created = true;
        group.status = "resharing".into();
        assert_eq!(
            membership_change(&group, &[], &["carol".into()], &[]).unwrap_err(),
            "Дождитесь завершения текущего пересчёта долей"
        );
    }

    #[test]
    fn rejects_a_seventeenth_member_and_a_used_up_identifier() {
        let members = (1..=MAX_SIGNERS)
            .map(|id| member(&format!("user{id}"), id, true))
            .collect();
        let group = active_group(2, members);
        assert_eq!(
            membership_change(&group, &[], &["extra".into()], &[]).unwrap_err(),
            format!("В группе не больше {MAX_SIGNERS} участников")
        );

        let group = active_group(
            2,
            vec![member("alice", 1, true), member("bob", u16::MAX, true)],
        );
        assert_eq!(
            membership_change(&group, &[], &["carol".into()], &[]).unwrap_err(),
            "Закончились идентификаторы участников"
        );
    }

    #[test]
    fn rejects_while_a_sign_request_is_open() {
        use ai_signing_protocol::SignRequestDto;
        let group = active_group(2, vec![member("alice", 1, true), member("bob", 2, true)]);
        let requests = vec![SignRequestDto {
            id: Uuid::new_v4(),
            group_id: group.id,
            group_name: group.name.clone(),
            message_hex: "00".into(),
            message_preview: "x".into(),
            status: "pending".into(),
            signature_hex: None,
            error: None,
            threshold: 2,
            approvals: 0,
            my_decision: None,
            created_at: String::new(),
            transaction: None,
        }];
        assert_eq!(
            membership_change(&group, &requests, &["carol".into()], &[]).unwrap_err(),
            "Дождитесь завершения текущей подписи"
        );
    }

    #[test]
    fn removing_a_member_without_a_device_key_is_allowed() {
        let group = active_group(
            2,
            vec![
                member("alice", 1, true),
                member("bob", 2, true),
                member("carol", 3, false),
            ],
        );
        let (add, remove) = membership_change(&group, &[], &[], &["carol".into()]).unwrap();
        assert!(add.is_empty());
        assert_eq!(remove, vec!["carol".to_string()]);
    }
}
