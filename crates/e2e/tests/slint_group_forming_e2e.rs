//! Slint headless: forming → подтверждение участия всеми → auto-DKG → active.

mod slint_group_support;

use std::path::{Path, PathBuf};
use ai_signing_protocol::GroupDto;
use slint_group_support::{admin, cli, progress, spawn_gui, write_plan};
use uuid::Uuid;

const GROUP: &str = "treasury";
const PASSWORD: &str = "password1";

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn slint_three_signers_accept_and_auto_dkg() {
    ai_signing_server::init_tracing();
    let state = ai_signing_server::bootstrap().await.expect("postgres");
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let admin_name = format!("sga_{suffix}");
    let signers: Vec<String> = vec![
        format!("sgs0_{suffix}"),
        format!("sgs1_{suffix}"),
        format!("sgs2_{suffix}"),
    ];

    for name in signers.iter().chain([&admin_name]) {
        let _ = ai_signing_server::delete_user(&state, name).await;
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        ai_signing_server::serve(listener, server_state)
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");

    let root = PathBuf::from(format!("/tmp/slint-forming-{suffix}"));
    std::fs::create_dir_all(&root).unwrap();
    let config = root.join("config.toml");
    std::fs::write(&config, format!("server = \"{base}\"\n")).unwrap();

    admin(
        &config,
        &["create-user", &admin_name, PASSWORD, "админ"],
    );
    for signer in &signers {
        admin(
            &config,
            &["create-user", signer, PASSWORD, "подписант"],
        );
    }

    let members_json = signers
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let signer_plan_template = format!(
        r#"{{
  "steps": [
    {{ "step": "login", "username": "USER", "password": "{PASSWORD}" }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "forming", "members": 3, "timeout_secs": 180 }},
    {{ "step": "select_group", "name": "{GROUP}" }},
    {{ "step": "accept_participation" }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "active", "members_with_keys": 3, "timeout_secs": 300 }},
    {{ "step": "done" }}
  ]
}}"#
    );

    let admin_plan = root.join("admin.plan.json");
    let signers_present_json = signers
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ");
    write_plan(
        &admin_plan,
        &format!(
            r#"{{
  "steps": [
    {{ "step": "login", "username": "{admin_name}", "password": "{PASSWORD}" }},
    {{ "step": "wait", "signers_present": [{signers_present_json}], "timeout_secs": 180 }},
    {{ "step": "create_group", "name": "{GROUP}", "threshold": 3, "members": [{members_json}] }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "active", "members_with_keys": 3, "timeout_secs": 300 }},
    {{ "step": "done" }}
  ]
}}"#
        ),
    );

    let mut signer_handles = Vec::new();
    for index in 0..signers.len() {
        let signer = signers[index].clone();
        let db = root.join(format!("signer{index}.sqlite"));
        let log = root.join(format!("signer{index}.log"));
        let plan = root.join(format!("signer{index}.plan.json"));
        write_plan(
            &plan,
            &signer_plan_template.replace("USER", &signer),
        );
        let config = config.clone();
        signer_handles.push(std::thread::spawn(move || {
            progress(format!("signer {signer} headless"));
            spawn_gui(&config, &db, &plan, &log)
        }));
    }

    let admin_db = root.join("admin.sqlite");
    let admin_log = root.join("admin.log");
    let config_admin = config.clone();
    let admin_db_thread = admin_db.clone();
    let admin_name_log = admin_name.clone();
    let admin_handle = std::thread::spawn(move || {
        progress(format!("admin {admin_name_log} headless"));
        spawn_gui(&config_admin, &admin_db_thread, &admin_plan, &admin_log)
    });

    for (index, handle) in signer_handles.into_iter().enumerate() {
        let output = handle.join().expect("signer join");
        assert!(
            output.status.success(),
            "signer {index} failed\nstdout: {}\nstderr tail in {}",
            String::from_utf8_lossy(&output.stdout),
            root.join(format!("signer{index}.log")).display()
        );
    }
    let admin_output = admin_handle.join().expect("admin join");
    assert!(
        admin_output.status.success(),
        "admin failed\nstdout: {}",
        String::from_utf8_lossy(&admin_output.stdout)
    );

    let group: GroupDto = cli(
        &config,
        &admin_db,
        &["group", &group_id(&config, &admin_db, GROUP)],
    );
    assert_eq!(group.status, "active");
    assert_eq!(group.members.len(), 3);
    assert!(
        group
            .members
            .iter()
            .all(|m| m.participation_accepted && m.box_public_hex.is_some()),
        "members: {:?}",
        group.members
    );
    let vk = group.verifying_key_hex.clone().expect("group vk");
    progress(format!("group {GROUP} active, vk {vk}"));

    for name in signers.iter().chain([&admin_name]) {
        ai_signing_server::delete_user(&state, name).await.unwrap();
    }
    let _ = std::fs::remove_dir_all(&root);
}

fn group_id(config: &Path, database: &Path, name: &str) -> String {
    let groups: Vec<GroupDto> = cli(config, database, &["groups"]);
    groups
        .into_iter()
        .find(|group| group.name == name)
        .expect("group")
        .id
        .to_string()
}
