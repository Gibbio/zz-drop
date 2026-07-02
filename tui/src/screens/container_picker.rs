//! Post-unlock picker — choose which inner profile to make active.
//!
//! Renders only when the unlocked container holds more than one inner
//! profile. With a single profile, the unlock flow skips straight to
//! `Screen::ProfileManage`.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use zz_drop_core::{PlainProfile, ProfileSet, ProviderProfile};

use crate::theme::{PanelAccent, Theme};
use crate::tui_widgets::{KeyHint, panel};

pub struct ContainerPickerScreen;

impl ContainerPickerScreen {
    pub fn title() -> &'static str {
        "select profile"
    }

    pub fn keybar_hint() -> Vec<KeyHint> {
        vec![
            KeyHint::new("↑↓", "navigate"),
            KeyHint::new("↵", "use"),
            KeyHint::new("esc", "lock"),
        ]
    }

    /// `default_alias` is the alias cached in
    /// `last-default-{local,remote}`; it gets a "(last used)" tag in
    /// the picker so the operator can confirm in muscle memory.
    pub fn render(
        area: Rect,
        buf: &mut Buffer,
        theme: &Theme,
        set: &ProfileSet,
        selected_index: usize,
        default_alias: Option<&str>,
    ) {
        let title = format!(" select profile ({} in container) ", set.profiles.len());
        let inner = panel::open(area, buf, theme, PanelAccent::Mint, &title);
        if inner.height < 4 {
            return;
        }

        // One row per inner profile, then a help line at the bottom.
        let mut constraints: Vec<Constraint> = Vec::with_capacity(set.profiles.len() + 2);
        constraints.push(Constraint::Length(1));
        for _ in &set.profiles {
            constraints.push(Constraint::Length(1));
        }
        constraints.push(Constraint::Min(1));
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(inner);

        // Top spacer line.
        let _ = chunks[0];

        for (i, profile) in set.profiles.iter().enumerate() {
            let row = chunks[1 + i];
            render_row(
                row,
                buf,
                theme,
                profile,
                i == selected_index,
                default_alias,
            );
        }
        // Trailing whitespace fills `chunks.last()` — the keybar at
        // the bottom of the screen already says ↑/↓ · ↵ · esc.
    }
}

fn render_row(
    area: Rect,
    buf: &mut Buffer,
    theme: &Theme,
    profile: &PlainProfile,
    selected: bool,
    default_alias: Option<&str>,
) {
    // Layout: "<cursor><star><alias><spacer><provider><spacer><default-tag>"
    // - cursor:  '> ' on the highlighted row, '  ' elsewhere
    // - star:    '★ ' on the cached-default row, '  ' elsewhere
    // - default-tag: '· default' in cyan, only on the default row
    let is_default = default_alias == Some(profile.alias.as_str());
    let cursor = if selected { "> " } else { "  " };
    let cursor_style = if selected {
        theme.accent_bold()
    } else {
        theme.dim()
    };
    let star = if is_default { "★ " } else { "  " };
    let star_style = if is_default {
        theme.cyan()
    } else {
        theme.dim()
    };
    let alias_style = match (selected, is_default) {
        (true, _) => theme.accent_bold(),
        (false, true) => theme.header(),
        (false, false) => theme.body(),
    };
    let provider_label = provider_summary(profile);

    let mut spans = vec![
        Span::styled(cursor.to_string(), cursor_style),
        Span::styled(star.to_string(), star_style),
        Span::styled(profile.alias.clone(), alias_style),
        Span::styled(format!("   {provider_label}"), theme.dim()),
    ];
    if is_default {
        spans.push(Span::styled("   · default", theme.cyan()));
    }
    let p = Paragraph::new(Line::from(spans));
    ratatui::widgets::Widget::render(p, area, buf);
}

fn provider_summary(profile: &PlainProfile) -> &'static str {
    match profile.providers.first() {
        Some(ProviderProfile::Nextcloud(_)) => "Nextcloud · WebDAV",
        Some(ProviderProfile::GoogleDrive(_)) => "Google Drive · OAuth",
        Some(ProviderProfile::OneDrive(_)) => "OneDrive · OAuth",
        Some(ProviderProfile::Dropbox(_)) => "Dropbox · OAuth",
        Some(ProviderProfile::Unknown(_)) => "unsupported · upgrade zz-drop",
        None => "—",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{MockEnv, Theme};
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use zz_drop_core::{
        CollisionPolicy, NextcloudAuth, NextcloudProfile, ProfileSettings, ProviderProfile,
    };

    fn t() -> Theme {
        Theme::from_parts(&MockEnv::empty(), false)
    }

    fn nc_profile(alias: &str) -> PlainProfile {
        PlainProfile {
            profile_version: 1,
            profile_id: format!("p-{alias}"),
            alias: alias.into(),
            default_target: "nc".into(),
            providers: vec![ProviderProfile::Nextcloud(NextcloudProfile {
                server_url: "https://example.org".into(),
                username: "u".into(),
                auth: NextcloudAuth::AppPassword {
                    secret: "s".into(),
                },
                remote_root: "/".into(),
            })],
            collision_policy: CollisionPolicy::Rename,
            settings: ProfileSettings::default(),
            created_at: "x".into(),
            updated_at: "x".into(),
        }
    }

    fn render_to_string(area: Rect, set: &ProfileSet, sel: usize, def: Option<&str>) -> String {
        let mut buf = Buffer::empty(area);
        ContainerPickerScreen::render(area, &mut buf, &t(), set, sel, def);
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn lists_all_aliases_with_arrow_on_selected() {
        let mut set = ProfileSet::new();
        set.profiles.push(nc_profile("alpha"));
        set.profiles.push(nc_profile("beta"));
        set.profiles.push(nc_profile("gamma"));

        let area = Rect::new(0, 0, 70, 12);
        let out = render_to_string(area, &set, 1, None);

        assert!(out.contains("alpha"));
        assert!(out.contains("beta"));
        assert!(out.contains("gamma"));
        // The selected row is "beta" → arrow precedes it.
        let beta_line = out.lines().find(|l| l.contains("beta")).unwrap();
        assert!(beta_line.contains(">"), "expected `>` on selected row: `{beta_line}`");
        let alpha_line = out.lines().find(|l| l.contains("alpha")).unwrap();
        assert!(!alpha_line.contains(">"), "alpha should not be selected: `{alpha_line}`");
    }

    #[test]
    fn default_marker_appears_on_default_alias_row() {
        let mut set = ProfileSet::new();
        set.profiles.push(nc_profile("alpha"));
        set.profiles.push(nc_profile("beta"));

        let area = Rect::new(0, 0, 70, 10);
        let out = render_to_string(area, &set, 0, Some("beta"));
        let beta_line = out.lines().find(|l| l.contains("beta")).unwrap();
        assert!(
            beta_line.contains('★'),
            "missing star marker on default row: `{beta_line}`"
        );
        assert!(
            beta_line.contains("default"),
            "missing `default` tag on default row: `{beta_line}`"
        );
        // Non-default rows should NOT carry either marker.
        let alpha_line = out.lines().find(|l| l.contains("alpha")).unwrap();
        assert!(
            !alpha_line.contains('★'),
            "non-default row should not carry the star: `{alpha_line}`"
        );
    }

    #[test]
    fn shows_provider_label_per_row() {
        let mut set = ProfileSet::new();
        set.profiles.push(nc_profile("alpha"));
        let area = Rect::new(0, 0, 70, 8);
        let out = render_to_string(area, &set, 0, None);
        assert!(out.contains("Nextcloud"));
    }

    #[test]
    fn keybar_includes_navigation_and_use() {
        let hints = ContainerPickerScreen::keybar_hint();
        assert!(hints.iter().any(|k| k.label.contains("navigate")));
        assert!(hints.iter().any(|k| k.label.contains("use")));
    }
}
