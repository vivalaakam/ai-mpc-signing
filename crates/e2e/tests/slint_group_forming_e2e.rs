//! Slint headless: forming → auto-DKG → reshare (add/remove) с подтверждением новых участников.

mod slint_group_support;

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use slint_group_support::{
    admin, cli_fail, group_by_name, progress, write_plan, GuiJob,
};
use uuid::Uuid;

const GROUP: &str = "treasury";
const PASSWORD: &str = "password1";
const THRESHOLD: u16 = 2;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn slint_forming_dkg_and_reshare_membership() {
    ai_signing_server::init_tracing();
    let state = ai_signing_server::bootstrap().await.expect("postgres");
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let admin_name = format!("sga_{suffix}");
    let signers: Vec<String> = vec![
        format!("sgs0_{suffix}"),
        format!("sgs1_{suffix}"),
        format!("sgs2_{suffix}"),
    ];
    let joiner = format!("sgs3_{suffix}");

    for name in signers.iter().chain([&admin_name, &joiner]) {
        let _ = ai_signing_server::delete_user(&state, name).await;
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn({
        let server_state = state.clone();
        async move {
            ai_signing_server::serve(listener, server_state)
                .await
                .unwrap();
        }
    });
    let base = format!("http://{addr}");

    let root = PathBuf::from(format!("/tmp/slint-forming-{suffix}"));
    std::fs::create_dir_all(&root).unwrap();
    let config = root.join("config.toml");
    std::fs::write(&config, format!("server = \"{base}\"\n")).unwrap();
    let admin_db = root.join("admin.sqlite");

    admin(&config, &["create-user", &admin_name, PASSWORD, "админ"]);
    for signer in signers.iter().chain([&joiner]) {
        admin(&config, &["create-user", signer, PASSWORD, "подписант"]);
    }

    run_forming_dkg(&root, &config, &admin_db, &admin_name, &signers).await;

    progress("reshare: замена sgs2 на sgs3");
    run_reshare_swap(&root, &config, &admin_db, &admin_name, &signers, &joiner).await;

    progress("reshare: удаление sgs3");
    run_reshare_remove(&root, &config, &admin_db, &admin_name, &signers, &joiner).await;

    let gid = group_by_name(&config, &admin_db, GROUP).id.to_string();
    let err = cli_fail(
        &config,
        &admin_db,
        &[
            "reshare",
            &gid,
            "remove",
            &signers[0],
            "remove",
            &signers[1],
        ],
    );
    assert!(
        err.contains("после изменения состава") || err.contains("порог"),
        "ожидали отказ по кворуму: {err}"
    );

    for name in signers.iter().chain([&admin_name, &joiner]) {
        ai_signing_server::delete_user(&state, name).await.unwrap();
    }
    let _ = std::fs::remove_dir_all(&root);
}

async fn run_forming_dkg(
    root: &PathBuf,
    config: &PathBuf,
    admin_db: &PathBuf,
    admin_name: &str,
    signers: &[String],
) {
    let members_json = json_names(signers);
    let signers_present = json_names(signers);

    let signer_plan = format!(
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

    write_plan(
        &root.join("admin-forming.plan.json"),
        &format!(
            r#"{{
  "steps": [
    {{ "step": "login", "username": "{admin_name}", "password": "{PASSWORD}" }},
    {{ "step": "wait", "signers_present": [{signers_present}], "timeout_secs": 180 }},
    {{ "step": "create_group", "name": "{GROUP}", "threshold": {THRESHOLD}, "members": [{members_json}] }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "active", "members_with_keys": 3, "timeout_secs": 300 }},
    {{ "step": "done" }}
  ]
}}"#
        ),
    );

    let mut jobs = Vec::new();
    for (index, signer) in signers.iter().enumerate() {
        let plan = root.join(format!("signer{index}-forming.plan.json"));
        write_plan(&plan, &signer_plan.replace("USER", signer));
        jobs.push(GuiJob::spawn(
            format!("signer{index} forming"),
            config.clone(),
            root.join(format!("signer{index}.sqlite")),
            plan,
            root.join(format!("signer{index}-forming.log")),
        ));
    }
    jobs.push(GuiJob::spawn(
        "admin forming",
        config.clone(),
        admin_db.clone(),
        root.join("admin-forming.plan.json"),
        root.join("admin-forming.log"),
    ));
    for job in jobs {
        job.join();
    }

    let group = group_by_name(config, admin_db, GROUP);
    assert_eq!(group.status, "active");
    assert_eq!(group.members.len(), 3);
    assert!(group.verifying_key_hex.is_some());
    progress(format!("forming+DKG ok, vk {}", group.verifying_key_hex.unwrap()));
}

async fn run_reshare_swap(
    root: &PathBuf,
    config: &PathBuf,
    admin_db: &PathBuf,
    admin_name: &str,
    signers: &[String],
    joiner: &str,
) {
    let removed = &signers[2];
    write_plan(
        &root.join("admin-swap.plan.json"),
        &format!(
            r#"{{
  "steps": [
    {{ "step": "login", "username": "{admin_name}", "password": "{PASSWORD}" }},
    {{ "step": "select_group", "name": "{GROUP}" }},
    {{ "step": "reshare", "add": ["{joiner}"], "remove": ["{removed}"] }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "active", "members": 3, "timeout_secs": 300 }},
    {{ "step": "done" }}
  ]
}}"#
        ),
    );

    let stayer_plan = format!(
        r#"{{
  "steps": [
    {{ "step": "login", "username": "USER", "password": "{PASSWORD}" }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "resharing", "timeout_secs": 180 }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "active", "members": 3, "timeout_secs": 300 }},
    {{ "step": "done" }}
  ]
}}"#
    );

    let joiner_plan = format!(
        r#"{{
  "steps": [
    {{ "step": "login", "username": "{joiner}", "password": "{PASSWORD}" }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "resharing", "members": 4, "timeout_secs": 180 }},
    {{ "step": "select_group", "name": "{GROUP}" }},
    {{ "step": "accept_participation" }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "active", "members": 3, "timeout_secs": 300 }},
    {{ "step": "done" }}
  ]
}}"#
    );

    write_plan(&root.join("joiner-swap.plan.json"), &joiner_plan);

    let s0_plan = root.join("signer0-swap.plan.json");
    write_plan(&s0_plan, &stayer_plan.replace("USER", &signers[0]));
    let s1_plan = root.join("signer1-swap.plan.json");
    write_plan(&s1_plan, &stayer_plan.replace("USER", &signers[1]));

    let j0 = GuiJob::spawn(
        "signer0 swap",
        config.clone(),
        root.join("signer0.sqlite"),
        s0_plan,
        root.join("signer0-swap.log"),
    );
    let j1 = GuiJob::spawn(
        "signer1 swap",
        config.clone(),
        root.join("signer1.sqlite"),
        s1_plan,
        root.join("signer1-swap.log"),
    );
    let j_joiner = GuiJob::spawn(
        "joiner swap",
        config.clone(),
        root.join("signer3.sqlite"),
        root.join("joiner-swap.plan.json"),
        root.join("joiner-swap.log"),
    );
    thread::sleep(Duration::from_secs(2));
    let admin_job = GuiJob::spawn(
        "admin swap",
        config.clone(),
        admin_db.clone(),
        root.join("admin-swap.plan.json"),
        root.join("admin-swap.log"),
    );
    j0.join();
    j1.join();
    j_joiner.join();
    admin_job.join();

    let group = group_by_name(config, admin_db, GROUP);
    assert_eq!(group.status, "active");
    assert_eq!(group.members.len(), 3);
    assert!(
        group.members.iter().any(|m| m.username == joiner),
        "joiner in roster: {:?}",
        group.members
    );
    assert!(
        !group.members.iter().any(|m| m.username == *removed),
        "removed gone"
    );
}

async fn run_reshare_remove(
    root: &PathBuf,
    config: &PathBuf,
    admin_db: &PathBuf,
    admin_name: &str,
    signers: &[String],
    joiner: &str,
) {
    write_plan(
        &root.join("admin-remove.plan.json"),
        &format!(
            r#"{{
  "steps": [
    {{ "step": "login", "username": "{admin_name}", "password": "{PASSWORD}" }},
    {{ "step": "select_group", "name": "{GROUP}" }},
    {{ "step": "reshare", "add": [], "remove": ["{joiner}"] }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "active", "members": 2, "timeout_secs": 300 }},
    {{ "step": "done" }}
  ]
}}"#
        ),
    );

    let stayer_plan = |user: &str| {
        format!(
            r#"{{
  "steps": [
    {{ "step": "login", "username": "{user}", "password": "{PASSWORD}" }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "resharing", "timeout_secs": 180 }},
    {{ "step": "wait_group", "name": "{GROUP}", "status": "active", "members": 2, "timeout_secs": 300 }},
    {{ "step": "done" }}
  ]
}}"#
        )
    };

    let s0_plan = root.join("signer0-remove.plan.json");
    write_plan(&s0_plan, &stayer_plan(&signers[0]));
    let s1_plan = root.join("signer1-remove.plan.json");
    write_plan(&s1_plan, &stayer_plan(&signers[1]));

    let j0 = GuiJob::spawn(
        "signer0 remove",
        config.clone(),
        root.join("signer0.sqlite"),
        s0_plan,
        root.join("signer0-remove.log"),
    );
    let j1 = GuiJob::spawn(
        "signer1 remove",
        config.clone(),
        root.join("signer1.sqlite"),
        s1_plan,
        root.join("signer1-remove.log"),
    );
    thread::sleep(Duration::from_secs(2));
    let admin_job = GuiJob::spawn(
        "admin remove",
        config.clone(),
        admin_db.clone(),
        root.join("admin-remove.plan.json"),
        root.join("admin-remove.log"),
    );
    j0.join();
    j1.join();
    admin_job.join();

    let group = group_by_name(config, admin_db, GROUP);
    assert_eq!(group.status, "active");
    assert_eq!(group.members.len(), 2);
    assert_eq!(group.threshold, THRESHOLD);
    assert!(
        group
            .members
            .iter()
            .all(|m| m.participation_accepted && m.box_public_hex.is_some())
    );
    let vk = group.verifying_key_hex.clone().expect("vk after remove");
    progress(format!("remove ok, 2 members, vk {vk}"));
}

fn json_names(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ")
}
