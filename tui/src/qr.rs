use image::{DynamicImage, ImageBuffer, Rgba};
use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui_image::Resize;
use ratatui_image::picker::{Picker, ProtocolType};

/// Wrapper around `Picker` so we can hold an optional graphics
/// detection result in the App without the caller having to know
/// ratatui-image's types.
pub struct GraphicsCtx {
    pub picker: Picker,
}

impl GraphicsCtx {
    /// Try to detect inline-graphics support based on environment
    /// variables that identify the host terminal. Only terminals on the
    /// allowlist below get inline graphics by default — for everything
    /// else (including emulators that *advertise* inline support but
    /// either misrender or prompt for permission) the caller should
    /// fall back to the half-block ASCII renderer.
    ///
    /// Allowlist (no per-frame prompt, known to render the protocol):
    /// - Kitty (`$KITTY_WINDOW_ID` set, or `$TERM=xterm-kitty`)
    /// - WezTerm (`$TERM_PROGRAM=WezTerm`)
    /// - Ghostty (`$TERM_PROGRAM=ghostty`, or `$GHOSTTY_RESOURCES_DIR` set)
    ///
    /// Deliberately **excluded** from the default:
    /// - iTerm2 — works, but pops "Allow this terminal to display a
    ///   file?" the first time per session. Users who want inline can
    ///   click "Always allow" and re-launch with
    ///   `ZZ_DROP_TUI_INLINE_QR=1`, which bypasses the allowlist.
    /// - Apple Terminal — no inline-image support at all.
    /// - Anything else — too easy for `ratatui-image` to misdetect.
    ///
    /// `force` is used by the env-var opt-in path to skip the allowlist.
    pub fn detect_with(force: bool) -> Option<Self> {
        let kind = TerminalKind::from_env();
        if !force && !kind.is_inline_safe() {
            return None;
        }
        let mut picker = Picker::from_query_stdio().ok()?;
        if let Some(forced) = kind.preferred_protocol() {
            picker.set_protocol_type(forced);
        }
        Some(Self { picker })
    }

    /// Backwards-compatible default-detect. Equivalent to
    /// `detect_with(false)` — returns `Some` only on the allowlist.
    pub fn detect() -> Option<Self> {
        Self::detect_with(false)
    }
}

/// Coarse classification of the host terminal. Used to decide whether
/// inline graphics are safe to attempt and which protocol to force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalKind {
    Kitty,
    WezTerm,
    Ghostty,
    Iterm2,
    AppleTerminal,
    Other,
}

impl TerminalKind {
    fn from_env() -> Self {
        let term_program = std::env::var("TERM_PROGRAM").unwrap_or_default();
        let term = std::env::var("TERM").unwrap_or_default();
        if std::env::var_os("KITTY_WINDOW_ID").is_some() || term == "xterm-kitty" {
            return Self::Kitty;
        }
        if term_program == "WezTerm" {
            return Self::WezTerm;
        }
        if term_program == "ghostty" || std::env::var_os("GHOSTTY_RESOURCES_DIR").is_some() {
            return Self::Ghostty;
        }
        if term_program == "iTerm.app" {
            return Self::Iterm2;
        }
        if term_program == "Apple_Terminal" {
            return Self::AppleTerminal;
        }
        Self::Other
    }

    /// Is the terminal known to display inline images quietly (no
    /// permission prompt) and reliably (renders the bytes the picker
    /// would emit, given the override below)? When this is `false` the
    /// default `detect()` path returns `None` and the TUI uses ASCII.
    fn is_inline_safe(self) -> bool {
        matches!(self, Self::Kitty | Self::WezTerm | Self::Ghostty)
    }

    /// Override the picker's auto-detection. `ratatui-image`'s detector
    /// occasionally misclassifies the protocol (iTerm2 ↔ Kitty in
    /// particular); when we know the exact terminal we set it directly.
    fn preferred_protocol(self) -> Option<ProtocolType> {
        match self {
            Self::Kitty | Self::WezTerm | Self::Ghostty => Some(ProtocolType::Kitty),
            Self::Iterm2 => Some(ProtocolType::Iterm2),
            Self::AppleTerminal | Self::Other => None,
        }
    }
}

/// Render the QR for `text` as an inline image inside `area`, using
/// the detected protocol. Returns `false` if the image renderer
/// couldn't be initialised — the caller should fall back to the
/// half-block ASCII renderer.
pub fn render_qr_image(
    text: &str,
    area: Rect,
    frame: &mut Frame<'_>,
    graphics: &mut GraphicsCtx,
) -> bool {
    // The picker defaults to `Halfblocks` when the terminal didn't report a
    // real graphics protocol. In that case our handcrafted ASCII renderer
    // (1 cell per QR module horizontally) is sharper than letting
    // ratatui-image downscale the PNG into half-blocks. So we only try the
    // inline path on terminals with real graphics support.
    if matches!(graphics.picker.protocol_type(), ProtocolType::Halfblocks) {
        return false;
    }

    let dyn_img = match build_qr_image(text) {
        Some(i) => i,
        None => return false,
    };

    match graphics
        .picker
        .new_protocol(dyn_img, area.into(), Resize::Fit(None))
    {
        Ok(protocol) => {
            let widget = ratatui_image::Image::new(&protocol);
            frame.render_widget(widget, area);
            true
        }
        Err(_) => false,
    }
}

fn build_qr_image(text: &str) -> Option<DynamicImage> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let width = code.width() as u32;
    let modules = code.to_colors();

    // Each module = N×N pixels; 4-module quiet zone on each side.
    const SCALE: u32 = 8;
    const QUIET: u32 = 4;
    let img_size = (width + 2 * QUIET) * SCALE;

    let mut img: ImageBuffer<Rgba<u8>, Vec<u8>> =
        ImageBuffer::from_pixel(img_size, img_size, Rgba([255, 255, 255, 255]));

    for y in 0..width {
        for x in 0..width {
            if modules[(y * width + x) as usize] == qrcode::Color::Dark {
                let px0 = (x + QUIET) * SCALE;
                let py0 = (y + QUIET) * SCALE;
                for dy in 0..SCALE {
                    for dx in 0..SCALE {
                        img.put_pixel(px0 + dx, py0 + dy, Rgba([0, 0, 0, 255]));
                    }
                }
            }
        }
    }

    Some(DynamicImage::ImageRgba8(img))
}

/// Returns the half-block `(outer_width, outer_height)` a panel needs in
/// order to host a scanable QR for `text`. The numbers include:
/// - 1-cell quiet zone on each side
/// - 2 horizontal cells for the panel's left/right borders
/// - 1 row for the panel title strip + 2 rows top/bottom borders
///
/// Half-block keeps the QR aspect ratio close to 1:1 on terminals with
/// 1×2 cell ratios, which is what phone QR scanners expect. Returns
/// `None` only if the URL is empty enough that `qrcode` rejects it.
pub fn qr_outer_size(text: &str) -> Option<(u16, u16)> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let modules = code.width();
    let inner_w = (modules + 2) as u16;
    let inner_h = modules.div_ceil(2) as u16;
    Some((inner_w + 2, inner_h + 3))
}

/// ASCII renderer — works on any terminal. Tries half-block (sharpest,
/// 1 cell = 1×2 modules) first; if the area is too small, falls back to
/// quadrant blocks (1 cell = 2×2 modules), which halves both axes at the
/// cost of some scanability. If even the quadrant version doesn't fit,
/// emits a one-line diagnostic so the operator knows to enlarge the pane.
pub fn render_qr(text: &str, area: Rect, buf: &mut Buffer) {
    let code = match qrcode::QrCode::new(text.as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            let p = Paragraph::new("(qr encoding failed)");
            ratatui::widgets::Widget::render(p, area, buf);
            return;
        }
    };

    let width = code.width();
    let modules: Vec<bool> = code
        .to_colors()
        .iter()
        .map(|c| *c == qrcode::Color::Dark)
        .collect();

    let half_w = (width + 2) as u16;
    let half_h = width.div_ceil(2) as u16;
    if area.width >= half_w && area.height >= half_h {
        render_half_block(&modules, width, area, buf);
        return;
    }

    let quad_w = (width.div_ceil(2) + 2) as u16;
    let quad_h = width.div_ceil(2) as u16;
    if area.width >= quad_w && area.height >= quad_h {
        render_quadrant(&modules, width, area, buf);
        return;
    }

    let p = Paragraph::new(format!(
        "(qr needs {half_w}x{half_h} half-block or {quad_w}x{quad_h} quadrant; this pane is {}x{})",
        area.width, area.height
    ));
    ratatui::widgets::Widget::render(p, area, buf);
}

fn render_half_block(modules: &[bool], width: usize, area: Rect, buf: &mut Buffer) {
    let half_h = width.div_ceil(2);
    let mut lines: Vec<Line<'_>> = Vec::with_capacity(half_h);
    for row in 0..half_h {
        let y_top = row * 2;
        let y_bot = y_top + 1;
        let mut s = String::with_capacity(width + 2);
        s.push(' ');
        for x in 0..width {
            let top = modules[y_top * width + x];
            let bot = if y_bot < width {
                modules[y_bot * width + x]
            } else {
                false
            };
            s.push(match (top, bot) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        s.push(' ');
        lines.push(Line::from(Span::styled(s, Style::default())));
    }
    let p = Paragraph::new(lines);
    ratatui::widgets::Widget::render(p, area, buf);
}

fn render_quadrant(modules: &[bool], width: usize, area: Rect, buf: &mut Buffer) {
    // Pack a 2×2 module block into one cell using Unicode quadrant glyphs.
    // bit layout (UL, UR, LL, LR) → 4-bit nibble → glyph table.
    let cell_rows = width.div_ceil(2);
    let cell_cols = width.div_ceil(2);
    let module_at = |x: usize, y: usize| -> bool {
        if x < width && y < width {
            modules[y * width + x]
        } else {
            false
        }
    };
    let mut lines: Vec<Line<'_>> = Vec::with_capacity(cell_rows);
    for row in 0..cell_rows {
        let mut s = String::with_capacity(cell_cols + 2);
        s.push(' ');
        for col in 0..cell_cols {
            let x0 = col * 2;
            let y0 = row * 2;
            let ul = module_at(x0, y0);
            let ur = module_at(x0 + 1, y0);
            let ll = module_at(x0, y0 + 1);
            let lr = module_at(x0 + 1, y0 + 1);
            let nibble = (ul as u8) << 3 | (ur as u8) << 2 | (ll as u8) << 1 | lr as u8;
            s.push(QUADRANT[nibble as usize]);
        }
        s.push(' ');
        lines.push(Line::from(Span::styled(s, Style::default())));
    }
    let p = Paragraph::new(lines);
    ratatui::widgets::Widget::render(p, area, buf);
}

// Indexed by (UL << 3) | (UR << 2) | (LL << 1) | LR — values 0..=15.
const QUADRANT: [char; 16] = [
    ' ', // 0000
    '▗', // 0001 LR
    '▖', // 0010 LL
    '▄', // 0011 LL+LR
    '▝', // 0100 UR
    '▐', // 0101 UR+LR
    '▞', // 0110 UR+LL
    '▟', // 0111 UR+LL+LR
    '▘', // 1000 UL
    '▚', // 1001 UL+LR
    '▌', // 1010 UL+LL
    '▙', // 1011 UL+LL+LR
    '▀', // 1100 UL+UR
    '▜', // 1101 UL+UR+LR
    '▛', // 1110 UL+UR+LL
    '█', // 1111 all
];

#[cfg(test)]
mod tests {
    use super::*;

    // We can't drive `TerminalKind::from_env` directly without leaking
    // env vars across parallel tests. Sanity-check the helpers instead.
    #[test]
    fn allowlist_picks_only_known_quiet_terminals() {
        for k in [
            TerminalKind::Kitty,
            TerminalKind::WezTerm,
            TerminalKind::Ghostty,
        ] {
            assert!(k.is_inline_safe(), "{k:?} should be on the allowlist");
            assert_eq!(k.preferred_protocol(), Some(ProtocolType::Kitty));
        }
        for k in [
            TerminalKind::Iterm2,
            TerminalKind::AppleTerminal,
            TerminalKind::Other,
        ] {
            assert!(!k.is_inline_safe(), "{k:?} should NOT be on the allowlist");
        }
        assert_eq!(
            TerminalKind::Iterm2.preferred_protocol(),
            Some(ProtocolType::Iterm2),
            "iTerm2 force-override must still emit the right protocol when force=true"
        );
        assert_eq!(TerminalKind::AppleTerminal.preferred_protocol(), None);
        assert_eq!(TerminalKind::Other.preferred_protocol(), None);
    }

    #[test]
    fn render_qr_does_not_panic_on_tiny_area() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 5, 5));
        render_qr("https://example.org", Rect::new(0, 0, 5, 5), &mut buf);
    }

    #[test]
    fn render_qr_fits_in_normal_area() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 30));
        render_qr("https://example.org/login", Rect::new(0, 0, 80, 30), &mut buf);
    }

    #[test]
    fn build_qr_image_produces_an_image() {
        let img = build_qr_image("https://example.org/login").unwrap();
        assert!(img.width() > 0);
        assert!(img.height() > 0);
        assert_eq!(img.width(), img.height(), "QR is square");
    }
}
