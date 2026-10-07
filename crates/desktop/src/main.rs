use std::collections::HashSet;

use ai_signing_client::{
    listen, parse_args, role_title, Cmd, Config, GroupDto, SignRequestDto, Store, UiState,
};
use async_channel::Sender;
use gpui_kit::component::{
    button::{Button, ButtonVariants as _},
    clipboard::Clipboard,
    h_flex,
    input::{Input, InputState},
    scroll::ScrollableElement as _,
    v_flex, ActiveTheme as _, Disableable as _,
};
use gpui_kit::{
    div, point, prelude::*, px, size, App, Bounds, Context, Entity, IntoElement, Render,
    TitlebarOptions, Window, WindowBounds, WindowOptions,
};
use uuid::Uuid;

fn main() {
    let launch = match parse_args(std::env::args().skip(1)) {
        Ok(launch) => launch,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    if launch.rest.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Подпись MPC\n\n  ai-signing-gui [--config ПУТЬ] [--database ПУТЬ]\n\nАдрес сервера задаётся в конфиге, поле server."
        );
        return;
    }
    if let Some(extra) = launch.rest.first() {
        eprintln!("неизвестный аргумент: {extra}");
        std::process::exit(1);
    }
    let config = match Config::load(&launch.config_path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let store = match Store::open_path(&launch.database_path) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("не удалось открыть локальную базу: {err}");
            std::process::exit(1);
        }
    };
    let (listener, _socket) = match listen(&launch.database_path) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let server = config.server_url();
    let initial = UiState::from_store(&store, &server);
    let (commands, events) = ai_signing_client::start(store, server, listener);

    gpui_kit::application().run(move |cx| {
        gpui_kit::init(cx);
        let commands = commands.clone();
        let initial = initial.clone();
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds {
                origin: point(px(80.), px(48.)),
                size: size(px(1100.), px(740.)),
            })),
            titlebar: Some(TitlebarOptions {
                title: Some("Подпись MPC".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        gpui_kit::open_window(options, cx, move |window, cx| {
            cx.new(|cx| AppView::new(window, cx, commands, events, initial))
        })
        .expect("не удалось открыть окно");
    });
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Groups,
    Inbox,
}

struct AppView {
    commands: Sender<Cmd>,
    state: UiState,
    busy: bool,
    tab: Tab,
    selected: Option<Uuid>,
    username: Entity<InputState>,
    password: Entity<InputState>,
    group_name: Entity<InputState>,
    threshold: Entity<InputState>,
    picked: HashSet<String>,
}

impl AppView {
    fn new(
        window: &mut Window,
        cx: &mut Context<Self>,
        commands: Sender<Cmd>,
        events: async_channel::Receiver<UiState>,
        initial: UiState,
    ) -> Self {
        let username = cx.new(|cx| InputState::new(window, cx).placeholder("имя"));
        let password = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("пароль")
                .masked(true)
        });
        let group_name = cx.new(|cx| InputState::new(window, cx).placeholder("название группы"));
        let threshold = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("2")
                .default_value("2")
        });
        cx.spawn(async move |this, cx| {
            while let Ok(event) = events.recv().await {
                if this
                    .update(cx, |view, cx| {
                        view.apply(event);
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        Self {
            commands,
            state: initial,
            busy: false,
            tab: Tab::Groups,
            selected: None,
            username,
            password,
            group_name,
            threshold,
            picked: HashSet::new(),
        }
    }

    fn apply(&mut self, state: UiState) {
        let known: HashSet<Uuid> = self.state.groups.iter().map(|group| group.id).collect();
        let fresh = state
            .groups
            .iter()
            .find(|group| !known.contains(&group.id))
            .map(|group| group.id);
        let ids: Vec<Uuid> = state.groups.iter().map(|group| group.id).collect();
        if let Some(id) = fresh {
            self.selected = Some(id);
        } else if self.selected.is_some_and(|id| !ids.contains(&id)) || self.selected.is_none() {
            self.selected = ids.first().copied();
        }
        if state.notice.as_deref() == Some("Группа создана") {
            self.picked.clear();
        }
        self.state = state;
        self.busy = false;
    }

    fn send(&mut self, cmd: Cmd, cx: &mut Context<Self>) {
        self.busy = true;
        self.state.error = None;
        self.state.notice = None;
        if self.commands.try_send(cmd).is_err() {
            self.busy = false;
            self.state.error = Some("Фоновая служба остановилась".into());
        }
        cx.notify();
    }

    fn login_screen(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity();
        let username = self.username.clone();
        let password = self.password.clone();
        let busy = self.busy;
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .gap_4()
            .child(div().text_xl().child("Подпись MPC"))
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("Пороговая подпись Ed25519. Доля ключа остаётся на этом устройстве."),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(format!("Сервер {}", self.state.server_url)),
            )
            .child(labeled(
                "Имя",
                Input::new(&self.username).id("username").w(px(360.)),
                cx,
            ))
            .child(labeled(
                "Пароль",
                Input::new(&self.password).id("password").w(px(360.)),
                cx,
            ))
            .child(
                Button::new("login")
                    .primary()
                    .label("Войти")
                    .disabled(busy)
                    .on_click(move |_, _, cx| {
                        let name = username.read(cx).value().to_string();
                        let pass = password.read(cx).value().to_string();
                        view.update(cx, |this, cx| {
                            if name.trim().is_empty() || pass.is_empty() {
                                this.state.error = Some("Введите имя и пароль".into());
                                this.busy = false;
                                cx.notify();
                                return;
                            }
                            this.send(
                                Cmd::Login {
                                    username: name.trim().to_string(),
                                    password: pass,
                                },
                                cx,
                            );
                        });
                    }),
            )
    }

    fn workspace(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let username = self.state.username.clone().unwrap_or_default();
        let link = if self.state.connected {
            "на связи"
        } else {
            "нет связи"
        };
        let link_color = if self.state.connected {
            cx.theme().success
        } else {
            cx.theme().muted_foreground
        };
        let pending = self
            .state
            .requests
            .iter()
            .filter(|request| request.status == "pending" && request.my_decision.is_none())
            .count();
        let inbox = if pending == 0 {
            "На подпись".to_string()
        } else {
            format!("На подпись ({pending})")
        };
        v_flex()
            .size_full()
            .child(self.header(&username, link, link_color, cx))
            .child(self.tabs(&inbox, cx))
            .child(
                div()
                    .flex_1()
                    .min_h(px(0.))
                    .p_4()
                    .child(if self.tab == Tab::Groups {
                        self.groups_page(cx).into_any_element()
                    } else {
                        self.inbox_page(cx).into_any_element()
                    }),
            )
    }

    fn header(
        &mut self,
        username: &str,
        link: &str,
        link_color: gpui_kit::Hsla,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let view = cx.entity();
        h_flex()
            .w_full()
            .px_4()
            .py_3()
            .justify_between()
            .items_center()
            .border_b_1()
            .border_color(cx.theme().border)
            .child(
                h_flex()
                    .gap_3()
                    .items_center()
                    .child(div().child("Подпись"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "{username} · {}",
                                role_title(self.state.role.as_deref().unwrap_or(""))
                            )),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(self.state.server_url.clone()),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(link_color)
                            .child(link.to_string()),
                    ),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child({
                        let view = view.clone();
                        Button::new("refresh")
                            .ghost()
                            .label("Обновить")
                            .disabled(self.busy)
                            .on_click(move |_, _, cx| {
                                view.update(cx, |this, cx| this.send(Cmd::Refresh, cx));
                            })
                    })
                    .child(Button::new("logout").ghost().label("Выйти").on_click(
                        move |_, _, cx| {
                            view.update(cx, |this, cx| this.send(Cmd::Logout, cx));
                        },
                    )),
            )
    }

    fn tabs(&mut self, inbox: &str, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity();
        let groups = tab_button("tab-groups", "Группы", self.tab == Tab::Groups, {
            let view = view.clone();
            move |cx: &mut App| {
                view.update(cx, |this, cx| {
                    this.tab = Tab::Groups;
                    cx.notify();
                });
            }
        });
        let inbox = tab_button(
            "tab-inbox",
            inbox,
            self.tab == Tab::Inbox,
            move |cx: &mut App| {
                view.update(cx, |this, cx| {
                    this.tab = Tab::Inbox;
                    cx.notify();
                });
            },
        );
        h_flex().px_4().pt_3().gap_2().child(groups).child(inbox)
    }

    fn groups_page(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let selected = self
            .selected
            .and_then(|id| self.state.groups.iter().find(|group| group.id == id))
            .cloned();
        h_flex()
            .size_full()
            .gap_4()
            .items_start()
            .child(
                v_flex()
                    .w(px(320.))
                    .h_full()
                    .gap_3()
                    .child(self.create_form(cx))
                    .child(
                        div()
                            .id("group-list")
                            .flex_1()
                            .min_h(px(0.))
                            .overflow_y_scrollbar()
                            .child(self.group_list(cx)),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .h_full()
                    .min_w(px(0.))
                    .id("group-detail")
                    .overflow_y_scrollbar()
                    .child(match selected {
                        Some(group) => self.group_detail(&group, cx).into_any_element(),
                        None => {
                            let text = if self.state.role.as_deref() == Some("admin") {
                                "Групп пока нет. Создайте группу и выберите подписантов."
                            } else {
                                "Групп пока нет. Администратор добавит вас в группу."
                            };
                            empty(text).into_any_element()
                        }
                    }),
            )
    }

    fn create_form(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        if self.state.role.as_deref() != Some("admin") {
            return div()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child("Группу создаёт администратор.")
                .into_any_element();
        }
        let view = cx.entity();
        let name = self.group_name.clone();
        let threshold = self.threshold.clone();
        let busy = self.busy;
        let signers = self.state.signers.clone();
        let picked = self.picked.clone();
        let mut signer_buttons = Vec::new();
        for signer in &signers {
            let username = signer.username.clone();
            let on = picked.contains(&username);
            let label = if on {
                format!("✓ {username}")
            } else {
                username.clone()
            };
            let view = view.clone();
            let mut button = Button::new(format!("signer-{username}"))
                .label(label)
                .w_full();
            button = if on { button.primary() } else { button.ghost() };
            signer_buttons.push(
                button
                    .on_click(move |_, _, cx| {
                        let username = username.clone();
                        view.update(cx, |this, cx| {
                            if !this.picked.insert(username.clone()) {
                                this.picked.remove(&username);
                            }
                            cx.notify();
                        });
                    })
                    .into_any_element(),
            );
        }
        v_flex()
            .gap_2()
            .p_3()
            .rounded(cx.theme().radius)
            .border_1()
            .border_color(cx.theme().border)
            .child(div().text_sm().child("Новая группа"))
            .child(Input::new(&self.group_name).id("group-name"))
            .child(labeled(
                "Порог t",
                Input::new(&self.threshold).id("threshold").w(px(88.)),
                cx,
            ))
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child("Активные подписанты"),
            )
            .child(
                div()
                    .id("signer-picker")
                    .h(px(180.))
                    .overflow_y_scrollbar()
                    .child(if signer_buttons.is_empty() {
                        div()
                            .text_sm()
                            .child("Нет активных подписантов. Подписант появляется здесь после входа в клиент.")
                            .into_any_element()
                    } else {
                        v_flex().gap_1().children(signer_buttons).into_any_element()
                    }),
            )
            .child(
                Button::new("create-group")
                    .primary()
                    .label("Создать группу")
                    .disabled(busy)
                    .on_click(move |_, _, cx| {
                        let name = name.read(cx).value().to_string();
                        let threshold = threshold.read(cx).value().to_string();
                        view.update(cx, |this, cx| {
                            let members: Vec<String> = this
                                .state
                                .signers
                                .iter()
                                .filter(|signer| this.picked.contains(&signer.username))
                                .map(|signer| signer.username.clone())
                                .collect();
                            match parse_threshold(&threshold, members.len()) {
                                Ok(threshold) => this.send(
                                    Cmd::CreateGroup {
                                        name: name.trim().to_string(),
                                        threshold,
                                        members,
                                    },
                                    cx,
                                ),
                                Err(err) => {
                                    this.state.error = Some(err);
                                    this.busy = false;
                                    cx.notify();
                                }
                            }
                        });
                    }),
            )
            .into_any_element()
    }

    fn group_list(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity();
        let selected = self.selected;
        v_flex()
            .gap_1()
            .children(self.state.groups.iter().map(|group| {
                let id = group.id;
                let label = format!(
                    "{} · {} · {}-из-{}",
                    group.name,
                    group_status(&group.status),
                    group.threshold,
                    group.max_signers
                );
                let view = view.clone();
                let mut button = Button::new(format!("group-{id}")).label(label).w_full();
                if selected == Some(id) {
                    button = button.primary();
                } else {
                    button = button.ghost();
                }
                button.on_click(move |_, _, cx| {
                    view.update(cx, |this, cx| {
                        this.selected = Some(id);
                        cx.notify();
                    });
                })
            }))
    }

    fn group_detail(&mut self, group: &GroupDto, cx: &mut Context<Self>) -> impl IntoElement {
        let has_share = self.state.shares.get(&group.id).copied().unwrap_or(false);
        let me = self.state.username.clone().unwrap_or_default();
        v_flex()
            .gap_3()
            .p_4()
            .rounded(cx.theme().radius)
            .border_1()
            .border_color(cx.theme().border)
            .child(
                h_flex()
                    .justify_between()
                    .items_center()
                    .child(div().text_lg().child(group.name.clone()))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "{} · порог {} из {}",
                                group_status(&group.status),
                                group.threshold,
                                group.max_signers
                            )),
                    ),
            )
            .child(div().text_sm().child(share_line(has_share, &group.status)))
            .child(self.member_block(group, &me, cx))
            .when(group.status == "forming" && group.i_created, |this| {
                this.child(self.forming_actions(group, cx))
            })
            .when(group.status == "dkg", |this| {
                this.child("Идёт распределённая генерация ключа. Это окно лучше не закрывать.")
            })
            .when(group.status == "failed", |this| {
                this.child("Генерация ключа не удалась. Создайте новую группу.")
            })
            .when(group.status == "active", |panel| {
                panel.child(self.active_block(group, cx))
            })
    }

    fn member_block(
        &mut self,
        group: &GroupDto,
        me: &str,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        v_flex()
            .gap_1()
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("Участники"),
            )
            .children(group.members.iter().map(|member| {
                let mut line = format!("{} · участник {}", member.username, member.identifier);
                if member.username == me {
                    line.push_str(" · вы");
                }
                if member.box_public_hex.is_none() {
                    line.push_str(" · нет ключа устройства");
                }
                div().text_sm().child(line)
            }))
            .when(group.members.is_empty(), |this| {
                this.child(div().text_sm().child("Пока никого нет."))
            })
    }

    fn forming_actions(&mut self, group: &GroupDto, cx: &mut Context<Self>) -> impl IntoElement {
        let group_id = group.id;
        let ready = group.members.len() == usize::from(group.max_signers)
            && group
                .members
                .iter()
                .all(|member| member.box_public_hex.is_some());
        let busy = self.busy;
        v_flex()
            .gap_2()
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("Перед запуском каждый подписант должен открыть клиент."),
            )
            .child(
                Button::new("start-dkg")
                    .primary()
                    .label("Запустить генерацию ключа")
                    .disabled(busy || !ready)
                    .on_click({
                        let view = cx.entity();
                        move |_, _, cx| {
                            view.update(cx, |this, cx| this.send(Cmd::StartDkg { group_id }, cx));
                        }
                    }),
            )
    }

    fn active_block(&mut self, group: &GroupDto, cx: &mut Context<Self>) -> impl IntoElement {
        let key = group.verifying_key_hex.clone().unwrap_or_default();
        v_flex()
            .gap_2()
            .when(!key.is_empty(), |this| {
                this.child(copy_line(
                    format!("vk-{}", group.id),
                    "Ключ проверки",
                    &key,
                    cx,
                ))
            })
            .when(group.api_token.is_some(), |this| {
                let token = group.api_token.clone().unwrap_or_default();
                this.child(copy_line(
                    format!("api-{}", group.id),
                    "Токен API",
                    &token,
                    cx,
                ))
                .child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child("Этим токеном внешний сервис создаёт запросы на подпись."),
                )
            })
    }

    fn inbox_page(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        if self.state.requests.is_empty() {
            return empty("Запросов на подпись нет.").into_any_element();
        }
        let requests = self.state.requests.clone();
        let mut cards = Vec::new();
        for request in &requests {
            cards.push(self.request_card(request, cx).into_any_element());
        }
        div()
            .id("inbox")
            .size_full()
            .overflow_y_scrollbar()
            .child(v_flex().gap_3().children(cards))
            .into_any_element()
    }

    fn request_card(
        &mut self,
        request: &SignRequestDto,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let has_share = self
            .state
            .shares
            .get(&request.group_id)
            .copied()
            .unwrap_or(false);
        let view = cx.entity();
        let request_id = request.id;
        let busy = self.busy;
        let can_decide = request.status == "pending" && request.my_decision.is_none();
        v_flex()
            .gap_2()
            .p_3()
            .rounded(cx.theme().radius)
            .border_1()
            .border_color(cx.theme().border)
            .child(
                h_flex()
                    .justify_between()
                    .child(div().child(request.group_name.clone()))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "{} · {} из {} · {}",
                                request_status(&request.status),
                                request.approvals,
                                request.threshold,
                                request.created_at.chars().take(16).collect::<String>()
                            )),
                    ),
            )
            .child(div().child(request.message_preview.clone()))
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .font_family(cx.theme().mono_font_family.clone())
                    .child(request.message_hex.clone()),
            )
            .when(can_decide && has_share, |this| {
                this.child(
                    h_flex()
                        .gap_2()
                        .child(
                            Button::new(format!("approve-{request_id}"))
                                .primary()
                                .label("Подписать")
                                .disabled(busy)
                                .on_click({
                                    let view = view.clone();
                                    move |_, _, cx| {
                                        view.update(cx, |this, cx| {
                                            this.send(Cmd::Approve { request_id }, cx)
                                        });
                                    }
                                }),
                        )
                        .child(
                            Button::new(format!("reject-{request_id}"))
                                .danger()
                                .label("Отклонить")
                                .disabled(busy)
                                .on_click(move |_, _, cx| {
                                    view.update(cx, |this, cx| {
                                        this.send(Cmd::Reject { request_id }, cx)
                                    });
                                }),
                        ),
                )
            })
            .when(can_decide && !has_share, |this| {
                this.child("На этом устройстве нет доли ключа, подтвердить подпись нельзя.")
            })
            .when(request.my_decision.as_deref() == Some("approved"), |this| {
                this.child("Вы подтвердили подпись.")
            })
            .when(request.my_decision.as_deref() == Some("rejected"), |this| {
                this.child("Вы отклонили запрос.")
            })
            .when(request.status == "signing", |this| {
                this.child("Идёт сбор подписи.")
            })
            .when(request.error.is_some(), |this| {
                this.child(
                    div()
                        .text_color(cx.theme().danger)
                        .child(request.error.clone().unwrap_or_default()),
                )
            })
            .when(request.signature_hex.is_some(), |this| {
                let signature = request.signature_hex.clone().unwrap_or_default();
                this.child(copy_line(
                    format!("sig-{request_id}"),
                    "Подпись",
                    &signature,
                    cx,
                ))
            })
    }
}

impl Render for AppView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let body = if self.state.username.is_none() {
            self.login_screen(cx).into_any_element()
        } else {
            self.workspace(cx).into_any_element()
        };
        v_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(body)
            .when(
                self.state.error.is_some() || self.state.notice.is_some(),
                |this| {
                    let (text, color) = if let Some(error) = &self.state.error {
                        (error.clone(), cx.theme().danger)
                    } else {
                        (
                            self.state.notice.clone().unwrap_or_default(),
                            cx.theme().success,
                        )
                    };
                    this.child(
                        div()
                            .w_full()
                            .px_4()
                            .py_2()
                            .border_t_1()
                            .border_color(cx.theme().border)
                            .text_sm()
                            .text_color(color)
                            .child(text),
                    )
                },
            )
    }
}

fn labeled(title: &str, input: impl IntoElement, cx: &App) -> impl IntoElement {
    v_flex()
        .gap_1()
        .child(
            div()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child(title.to_string()),
        )
        .child(input)
}

fn tab_button(
    id: &'static str,
    label: &str,
    active: bool,
    on_click: impl Fn(&mut App) + 'static,
) -> impl IntoElement {
    let label = label.to_string();
    let mut button = Button::new(id).label(label);
    button = if active {
        button.primary()
    } else {
        button.ghost()
    };
    button.on_click(move |_, _, cx| on_click(cx))
}

fn copy_line(id: String, title: &str, value: &str, cx: &App) -> impl IntoElement {
    h_flex()
        .gap_2()
        .items_center()
        .child(
            div()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child(title.to_string()),
        )
        .child(
            div()
                .text_sm()
                .font_family(cx.theme().mono_font_family.clone())
                .child(short_hex(value)),
        )
        .child(
            Clipboard::new(id)
                .value(value.to_string())
                .tooltip("Копировать"),
        )
}

fn empty(text: &str) -> impl IntoElement {
    div().p_4().child(text.to_string())
}

fn short_hex(value: &str) -> String {
    if value.len() <= 22 {
        value.to_string()
    } else {
        format!("{}…{}", &value[..10], &value[value.len() - 8..])
    }
}

fn group_status(status: &str) -> &str {
    match status {
        "forming" => "набор",
        "dkg" => "генерация ключа",
        "active" => "активна",
        "failed" => "ошибка",
        other => other,
    }
}

fn request_status(status: &str) -> &str {
    match status {
        "pending" => "ожидает",
        "signing" => "подпись",
        "completed" => "подписано",
        "failed" => "ошибка",
        other => other,
    }
}

fn share_line(has_share: bool, status: &str) -> String {
    if has_share {
        "Доля ключа хранится на этом устройстве.".into()
    } else if status == "active" || status == "dkg" {
        "Доли ключа на этом устройстве нет.".into()
    } else {
        "Доля появится после генерации ключа.".into()
    }
}

fn parse_threshold(threshold: &str, members: usize) -> Result<u16, String> {
    let threshold: u16 = threshold
        .trim()
        .parse()
        .map_err(|_| "Порог t должен быть числом".to_string())?;
    let members = u16::try_from(members).unwrap_or(u16::MAX);
    if members < 2 || members > 16 || !(2..=members).contains(&threshold) {
        return Err("Порог t и число подписантов: 2 ≤ t ≤ n ≤ 16".into());
    }
    Ok(threshold)
}
