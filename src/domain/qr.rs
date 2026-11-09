use std::fmt::Write;

use qrcode::{Color, QrCode};

use crate::error::Error;

const QUIET_ZONE: usize = 4;

/// An inline-ready SVG of the QR code; it takes its colour from the surrounding text colour.
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
        "<svg class=\"qr\" viewBox=\"0 0 {size} {size}\" role=\"img\" aria-label=\"QR code\" shape-rendering=\"crispEdges\"><path fill=\"currentColor\" d=\"{d}\"/></svg>"
    ))
}
