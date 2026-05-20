// Standalone inline-image QR test. Bypasses the wizard, the layout
// engine, and the screen-graph. Just opens an alt-screen, detects the
// terminal's inline-image protocol, generates a QR image and renders
// it via `ratatui-image::Image`. Press any key to exit.
//
// What you should see:
//   ┌─ qr_inline test ─────────────────────────────────┐
//   │  detected protocol: <Kitty | Iterm2 | Sixel | …> │
//   │  inline image:                                   │
//   │   ┌──────────┐                                   │
//   │   │ <QR pic> │                                   │
//   │   │          │                                   │
//   │   └──────────┘                                   │
//   │  press any key to exit                           │
//   └──────────────────────────────────────────────────┘
//
// If the inline image area is blank, your terminal claims to support
// the protocol but doesn't actually render it. In that case the TUI
// should default to the half-block ASCII renderer.

use std::io;
use std::time::Duration;

use image::{DynamicImage, ImageBuffer, Rgba};
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::buffer::Buffer;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};
use ratatui_image::Resize;
use ratatui_image::picker::{Picker, ProtocolType};

const URL: &str =
    "https://nextcloud.example.org/index.php/login/v2/flow/aBcD3FgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTu";

fn main() -> io::Result<()> {
    // Detect BEFORE entering alt screen — same as the real TUI does.
    let mut picker = match Picker::from_query_stdio() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Picker::from_query_stdio failed: {e}. Inline images not supported on this terminal.");
            return Ok(());
        }
    };
    let detected = picker.protocol_type();
    // Same override the real TUI applies: iTerm2 is misclassified as Kitty.
    if std::env::var("TERM_PROGRAM").as_deref() == Ok("iTerm.app") {
        picker.set_protocol_type(ProtocolType::Iterm2);
    }
    let proto = picker.protocol_type();

    let mut terminal = ratatui::init();

    let result = (|| -> io::Result<()> {
        let dyn_img = match build_qr_image(URL) {
            Some(i) => i,
            None => {
                eprintln!("could not encode QR for the URL");
                return Ok(());
            }
        };

        loop {
            terminal.draw(|frame| {
                draw(frame, proto, &mut picker, &dyn_img);
            })?;
            if event::poll(Duration::from_millis(200))?
                && let Event::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
            {
                break;
            }
        }
        Ok(())
    })();

    ratatui::restore();

    if let Err(e) = result {
        eprintln!("error: {e}");
    }
    println!("\ndetected by Picker: {detected:?}");
    println!("after override:    {proto:?}");
    println!("TERM_PROGRAM={}", std::env::var("TERM_PROGRAM").unwrap_or_default());
    println!("if the QR area was blank, your terminal advertises support but doesn't render it.");
    Ok(())
}

fn draw(frame: &mut Frame<'_>, proto: ProtocolType, picker: &mut Picker, dyn_img: &DynamicImage) {
    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" qr_inline test ");
    let inner = block.inner(area);
    Widget::render(block, area, frame.buffer_mut());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(inner);

    paragraph(
        chunks[0],
        frame.buffer_mut(),
        format!("detected protocol: {proto:?}"),
        Style::default().add_modifier(Modifier::BOLD),
    );
    paragraph(
        chunks[1],
        frame.buffer_mut(),
        "inline image:".into(),
        Style::default(),
    );

    // Carve a square area inside chunks[2] for the QR.
    let side = chunks[2].width.min(chunks[2].height * 2).min(30);
    let qr_area = Rect::new(
        chunks[2].x + 2,
        chunks[2].y,
        side,
        chunks[2].height.min(side / 2 + 2),
    );

    if matches!(proto, ProtocolType::Halfblocks) {
        paragraph(
            qr_area,
            frame.buffer_mut(),
            "(detected Halfblocks — inline image protocol not supported)".into(),
            Style::default(),
        );
    } else {
        match picker.new_protocol(dyn_img.clone(), qr_area.into(), Resize::Fit(None)) {
            Ok(protocol) => {
                let img = ratatui_image::Image::new(&protocol);
                frame.render_widget(img, qr_area);
            }
            Err(e) => {
                paragraph(
                    qr_area,
                    frame.buffer_mut(),
                    format!("new_protocol failed: {e}"),
                    Style::default(),
                );
            }
        }
    }

    paragraph(
        chunks[3],
        frame.buffer_mut(),
        "press any key to exit".into(),
        Style::default().add_modifier(Modifier::DIM),
    );
}

fn paragraph(area: Rect, buf: &mut Buffer, text: String, style: Style) {
    let p = Paragraph::new(Line::from(Span::styled(text, style)));
    Widget::render(p, area, buf);
}

fn build_qr_image(text: &str) -> Option<DynamicImage> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let width = code.width() as u32;
    let modules = code.to_colors();

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

// quiet ratatui re-export (avoids requiring an extra `use` for callers).
#[allow(dead_code)]
fn _terminal_alias() -> Option<Terminal<ratatui::backend::TestBackend>> {
    None
}
