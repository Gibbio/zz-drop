use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use zz_drop_core::{NextcloudAuth, PlainProfile, ProviderProfile};

use crate::app::ProfileSource;
use crate::theme::{PanelAccent, Theme};
use crate::tui_widgets::{KeyHint, panel};
use crate::wizard::ManageStage;

pub struct ProfileManageScreen;

impl ProfileManageScreen {
    pub fn title() -> &'static str {
        "manage profile"
    }

    pub fn keybar_hint(stage: &ManageStage, source: ProfileSource) -> Vec<KeyHint> {
        match stage {
            ManageStage::WipeConfirm => vec![
                KeyHint::new("y", "confirm wipe"),
                KeyHint::new("n", "cancel"),
            ],
            ManageStage::Wiping => vec![KeyHint::new("…", "wiping")],
            ManageStage::DeleteInnerConfirm => vec![
                KeyHint::new("y", "confirm delete"),
                KeyHint::new("n", "cancel"),
            ],
            ManageStage::DeletingInner => vec![KeyHint::new("…", "deleting")],
            _ => {
                // A `profiles-local.zz` was never sent to a server;
                // pushing it is a *first* push, not a re-push. A
                // `profiles-remote.zz` is by definition already on
                // the server, so updating it is a re-push.
                let push_label = match source {
                    ProfileSource::Local => "push to server",
                    ProfileSource::Remote => "re-push",
                };
                vec![
                    KeyHint::new("a", "add profile"),
                    KeyHint::new("p", push_label),
                    KeyHint::new("t", "re-test"),
                    KeyHint::new("r", "reveal pwd"),
                    KeyHint::new("D", "delete this"),
                    KeyHint::new("w", "wipe all"),
                    KeyHint::new("esc", "back"),
                ]
            }
        }
    }

    pub fn render(
        area: Rect,
        buf: &mut Buffer,
        theme: &Theme,
        profile: Option<&PlainProfile>,
        show_secret: bool,
        stage: &ManageStage,
        api_base: &str,
    ) {
        if matches!(stage, ManageStage::WipeConfirm | ManageStage::Wiping) {
            let alias = profile.map(|p| p.alias.as_str());
            render_wipe_confirm(area, buf, theme, stage, api_base, alias);
            return;
        }
        if matches!(
            stage,
            ManageStage::DeleteInnerConfirm | ManageStage::DeletingInner
        ) {
            let alias = profile.map(|p| p.alias.as_str()).unwrap_or("(unknown)");
            render_delete_inner_confirm(area, buf, theme, stage, alias);
            return;
        }
        // Outside the wipe sub-state we need the decrypted profile;
        // a missing one is a programming error (the caller should
        // route to ProfileUnlock instead) — render an empty panel.
        let Some(profile) = profile else {
            let _ = panel::open(area, buf, theme, PanelAccent::Mint, " profile ");
            return;
        };

        let title = format!(" profile · {} ", profile.alias);
        let inner = panel::open(area, buf, theme, PanelAccent::Mint, &title);
        if inner.height < 6 {
            return;
        }

        let nc = profile.providers.iter().find_map(|p| match p {
            ProviderProfile::Nextcloud(n) => Some(n),
            ProviderProfile::GoogleDrive(_)
            | ProviderProfile::OneDrive(_)
            | ProviderProfile::Dropbox(_)
            | ProviderProfile::Unknown(_) => None,
        });
        let gd = profile.providers.iter().find_map(|p| match p {
            ProviderProfile::GoogleDrive(g) => Some(g),
            ProviderProfile::Nextcloud(_)
            | ProviderProfile::OneDrive(_)
            | ProviderProfile::Dropbox(_)
            | ProviderProfile::Unknown(_) => None,
        });
        let od = profile.providers.iter().find_map(|p| match p {
            ProviderProfile::OneDrive(o) => Some(o),
            ProviderProfile::Nextcloud(_)
            | ProviderProfile::GoogleDrive(_)
            | ProviderProfile::Dropbox(_)
            | ProviderProfile::Unknown(_) => None,
        });
        let db = profile.providers.iter().find_map(|p| match p {
            ProviderProfile::Dropbox(d) => Some(d),
            ProviderProfile::Nextcloud(_)
            | ProviderProfile::GoogleDrive(_)
            | ProviderProfile::OneDrive(_)
            | ProviderProfile::Unknown(_) => None,
        });
        let has_unknown = profile
            .providers
            .iter()
            .any(|p| matches!(p, ProviderProfile::Unknown(_)));

        let provider_label = if nc.is_some() {
            "Nextcloud · WebDAV"
        } else if gd.is_some() {
            "Google Drive · OAuth"
        } else if od.is_some() {
            "OneDrive · OAuth"
        } else if db.is_some() {
            "Dropbox · OAuth"
        } else if has_unknown {
            "unsupported · upgrade zz-drop"
        } else {
            "—"
        };

        let mut lines: Vec<Line<'_>> = Vec::new();
        lines.push(Line::from(""));
        lines.push(field(theme, "alias", &profile.alias));
        lines.push(field(theme, "provider", provider_label));

        if let Some(nc) = nc {
            lines.push(field(theme, "server", &nc.server_url));
            lines.push(field(theme, "username", &nc.username));
            let (label, secret_str) = match &nc.auth {
                NextcloudAuth::AppPassword { secret } => ("app password", secret.as_str()),
                NextcloudAuth::LoginFlowToken { secret } => {
                    ("login-flow token", secret.as_str())
                }
            };
            let secret_line = if show_secret {
                field_styled(theme, label, secret_str, theme.body())
            } else {
                let masked = if secret_str.is_empty() {
                    "(unset)".to_string()
                } else {
                    format!("●●●●●●●●●●●●  (set, {} chars)", secret_str.chars().count())
                };
                field_styled(theme, label, &masked, theme.dim_bright())
            };
            lines.push(secret_line);
            lines.push(field(theme, "remote folder", &nc.remote_root));
        } else if let Some(gd) = gd {
            // OAuth profiles persist tokens, not a typed-by-user
            // password. They rotate transparently on every CLI run.
            // Show the long-lived metadata only — no `reveal` for
            // tokens here.
            lines.push(field(theme, "account", &gd.user_email));
            lines.push(field(theme, "folder", &gd.root_folder));
            let scope_short = gd
                .auth
                .scope
                .rsplit('/')
                .next()
                .unwrap_or(&gd.auth.scope);
            lines.push(field(theme, "scope", scope_short));
            lines.push(field_styled(
                theme,
                "tokens",
                "●●●●●●●●●●●●  (oauth, refreshed automatically)",
                theme.dim_bright(),
            ));
        } else if let Some(od) = od {
            lines.push(field(theme, "account", &od.user_email));
            lines.push(field(theme, "folder", &od.root_folder));
            // OneDrive scope is space-separated rather than slash-
            // separated, so just take the first scope token for a
            // compact label.
            let scope_short = od
                .auth
                .scope
                .split_whitespace()
                .next()
                .unwrap_or(&od.auth.scope);
            lines.push(field(theme, "scope", scope_short));
            lines.push(field_styled(
                theme,
                "tokens",
                "●●●●●●●●●●●●  (oauth, refreshed automatically)",
                theme.dim_bright(),
            ));
        }

        lines.push(field(
            theme,
            "collision",
            collision_label(profile.collision_policy),
        ));
        lines.push(Line::from(""));
        lines.push(field(theme, "created", &profile.created_at));
        lines.push(field(theme, "updated", &profile.updated_at));
        if nc.is_some() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  press r to reveal the app password (toggle).",
                theme.dim(),
            )));
        }

        let p = Paragraph::new(lines);
        let body_area =
            Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), inner.height);
        ratatui::widgets::Widget::render(p, body_area, buf);
    }
}

fn field(theme: &Theme, label: &str, value: &str) -> Line<'static> {
    field_styled(theme, label, value, theme.body())
}

fn field_styled(
    theme: &Theme,
    label: &str,
    value: &str,
    value_style: ratatui::style::Style,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {label:>14}  "), theme.dim()),
        Span::styled(value.to_string(), value_style),
    ])
}

fn collision_label(p: zz_drop_core::CollisionPolicy) -> &'static str {
    match p {
        zz_drop_core::CollisionPolicy::Rename => "rename",
        zz_drop_core::CollisionPolicy::Overwrite => "overwrite",
        zz_drop_core::CollisionPolicy::Fail => "fail",
    }
}

fn render_wipe_confirm(
    area: Rect,
    buf: &mut Buffer,
    theme: &Theme,
    stage: &ManageStage,
    api_base: &str,
    current_alias: Option<&str>,
) {
    let title = match current_alias {
        Some(a) => format!(" wipe local state · {a} "),
        None => " wipe local state ".to_string(),
    };
    let inner = panel::open(area, buf, theme, PanelAccent::Red, &title);
    if inner.height < 4 {
        return;
    }
    let body = if matches!(stage, ManageStage::Wiping) {
        Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  …  wiping local zz-drop state",
                theme.cyan(),
            )),
        ])
    } else {
        let alias = current_alias.unwrap_or("(no profile loaded)");
        let mut lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  ⚠  wipe local state for alias ", theme.warn()),
                Span::styled(format!("`{alias}`"), theme.accent_bold()),
                Span::styled("?", theme.warn()),
            ]),
            Line::from(""),
            Line::from(Span::styled("  this removes:", theme.dim())),
            Line::from(Span::styled(
                "    • profile.zz (the encrypted blob for this alias)",
                theme.dim(),
            )),
            Line::from(Span::styled("    • config.toml", theme.dim())),
            Line::from(Span::styled(
                "    • the local agent socket + token file",
                theme.dim(),
            )),
            Line::from(Span::styled(
                "    • the zz-drop runtime + config directories",
                theme.dim(),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  other aliases on your account are not affected — they live on",
                theme.dim(),
            )),
            Line::from(vec![
                Span::styled("  the server (", theme.dim()),
                Span::styled(api_base.to_string(), theme.cyan()),
                Span::styled(") and can be re-downloaded with", theme.dim()),
            ]),
            Line::from(Span::styled(
                "  `zz z <alias>` from any shell.",
                theme.dim(),
            )),
            Line::from(""),
        ];
        if current_alias.is_some() {
            lines.push(Line::from(vec![
                Span::styled("  if you previously pushed ", theme.dim()),
                Span::styled(format!("`{alias}`"), theme.accent_bold()),
                Span::styled(" to ", theme.dim()),
                Span::styled(api_base.to_string(), theme.cyan()),
                Span::styled(" you", theme.dim()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  can recover with ", theme.dim()),
                Span::styled(format!("`zz z {alias}`"), theme.accent_bold()),
                Span::styled(
                    ". otherwise this alias's encrypted blob is gone.",
                    theme.dim(),
                ),
            ]));
            lines.push(Line::from(""));
        }
        lines.push(Line::from(vec![
            Span::styled("  press ", theme.dim()),
            Span::styled("y", theme.accent_bold()),
            Span::styled(" to confirm, ", theme.dim()),
            Span::styled("n", theme.accent_bold()),
            Span::styled(" or ", theme.dim()),
            Span::styled("esc", theme.accent_bold()),
            Span::styled(" to cancel.", theme.dim()),
        ]));
        Paragraph::new(lines)
    };
    let body_area =
        Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), inner.height);
    ratatui::widgets::Widget::render(body, body_area, buf);
}

fn render_delete_inner_confirm(
    area: Rect,
    buf: &mut Buffer,
    theme: &Theme,
    stage: &ManageStage,
    alias: &str,
) {
    let title = format!(" delete profile · {alias} ");
    let inner = panel::open(area, buf, theme, PanelAccent::Red, &title);
    if inner.height < 4 {
        return;
    }
    let body = if matches!(stage, ManageStage::DeletingInner) {
        Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  …  removing profile from container",
                theme.cyan(),
            )),
        ])
    } else {
        let lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  ⚠  remove ", theme.warn()),
                Span::styled(format!("`{alias}`"), theme.accent_bold()),
                Span::styled(" from this container?", theme.warn()),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  the other inner profiles in the container are kept.",
                theme.dim(),
            )),
            Line::from(Span::styled(
                "  the container is re-encrypted in place with the cached",
                theme.dim(),
            )),
            Line::from(Span::styled(
                "  KEK — no passphrase prompt.",
                theme.dim(),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  files already uploaded to ", theme.dim()),
                Span::styled(format!("`{alias}`"), theme.accent_bold()),
                Span::styled(
                    "'s remote folder are NOT touched — log in to the",
                    theme.dim(),
                ),
            ]),
            Line::from(Span::styled(
                "  provider directly if you also want to clean those up.",
                theme.dim(),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  press ", theme.dim()),
                Span::styled("y", theme.accent_bold()),
                Span::styled(" to confirm, ", theme.dim()),
                Span::styled("n", theme.accent_bold()),
                Span::styled(" or ", theme.dim()),
                Span::styled("esc", theme.accent_bold()),
                Span::styled(" to cancel.", theme.dim()),
            ]),
        ];
        Paragraph::new(lines)
    };
    let body_area =
        Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), inner.height);
    ratatui::widgets::Widget::render(body, body_area, buf);
}
