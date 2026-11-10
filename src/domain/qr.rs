use std::fmt::Write;

use qrcode::{Color, QrCode};

use crate::error::Error;

const QUIET_ZONE: usize = 4;

/// An inline-ready SVG of the QR code with its own background (`qr-bg`) behind dark modules
/// (`qr-fg`); the stylesheet fills both, in the same light and dark pair in every theme so that
/// scanners always see dark on light.
pub fn svg(url: &str) -> Result<String, Error> {
    let code =
        QrCode::new(url.as_bytes()).map_err(|_| Error::Invalid("That address is too long for a QR code.".into()))?;
    let width = code.width();
    let size = width + 2 * QUIET_ZONE;
    let mut d = String::new();
    for (i, colour) in code.to_colors().into_iter().enumerate() {
        if colour == Color::Dark {
            let (x, y) = (i % width + QUIET_ZONE, i / width + QUIET_ZONE);
            let _ = write!(d, "M{x} {y}h1v1h-1z");
        }
    }
    Ok(format!(
        "<svg class=\"qr\" viewBox=\"0 0 {size} {size}\" role=\"img\" aria-label=\"QR code\" shape-rendering=\"crispEdges\"><rect class=\"qr-bg\" width=\"{size}\" height=\"{size}\"/><path class=\"qr-fg\" d=\"{d}\"/></svg>"
    ))
}
