pub mod admin;
pub mod docs;
pub mod errors;
pub mod files;
pub mod guide;
pub mod home;
pub mod list;
pub mod lookups;
pub mod multipart;
pub mod paste;
pub mod pwa;
pub mod shell;

use askama::Template;
use axum::response::Html;

use crate::domain::Privacy;
use crate::error::Error;
use crate::state::AppState;

/// Asset URLs a page adds to the shell's own.
#[derive(Debug, Default)]
pub struct Extras {
    pub css: Vec<String>,
    /// ES modules.
    pub js: Vec<String>,
    /// Classic deferred scripts, run before the modules.
    pub scripts: Vec<String>,
}

/// Wraps `body` (already-escaped HTML) in the page shell.
pub fn page(
    st: &AppState,
    admin: bool,
    current: &'static str,
    title: &str,
    body: String,
) -> Result<Html<String>, Error> {
    page_with(st, admin, current, title, body, Extras::default())
}

/// [`page`] with extra stylesheets and scripts.
pub fn page_with(
    st: &AppState,
    admin: bool,
    current: &'static str,
    title: &str,
    body: String,
    extras: Extras,
) -> Result<Html<String>, Error> {
    let layout = shell::Layout {
        title: title.to_owned(),
        current,
        body,
        admin,
        extra_css: extras.css,
        extra_js: extras.js,
        extra_scripts: extras.scripts,
        cfg: st.cfg.clone(),
    };
    layout.render().map(Html).map_err(Error::internal)
}

/// Renders a template, mapping a render failure to an internal error.
pub fn render(t: &impl Template) -> Result<String, Error> {
    t.render().map_err(Error::internal)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IconSize {
    Row,
    #[default]
    Tool,
    Tab,
}

/// The lucide icon inlined so it takes the surrounding text colour. An unknown name gives an
/// empty string, so a typo shows no icon rather than failing a request.
pub fn icon(name: &str, size: IconSize) -> String {
    let Some(file) = crate::assets::Assets::get(&format!("vendor/oc/icons/{name}.svg")) else {
        debug_assert!(false, "unknown icon {name}");
        return String::new();
    };
    let class = match size {
        IconSize::Row => "oc-icon oc-icon--row",
        IconSize::Tool => "oc-icon",
        IconSize::Tab => "oc-icon oc-icon--tab",
    };
    String::from_utf8_lossy(&file.data).trim_end().replacen(
        "class=\"oc-icon\"",
        &format!("class=\"{class}\" data-icon=\"{name}\""),
        1,
    )
}

/// Escapes text for an element body. Quotation marks stay as they are, which keeps messages
/// that quote the user's input readable in the source as well as on screen.
pub fn escape_text(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// `?deleted=word-word-word`, set by the delete redirect.
#[derive(Debug, Default, serde::Deserialize)]
pub struct DeletedQuery {
    pub deleted: Option<String>,
}

impl DeletedQuery {
    /// "Deleted 'x'", only for a well-formed paste address, so the page cannot be made to say anything else.
    pub fn notice(&self) -> Option<String> {
        let id = crate::domain::words::parse(self.deleted.as_deref()?).ok()?;
        Some(format!("Deleted '{}'", id.words()))
    }
}

pub fn privacy_label(p: Privacy) -> &'static str {
    match p {
        Privacy::Public => "Public",
        Privacy::Unlisted => "Unlisted",
        Privacy::Readonly => "Read-only",
        Privacy::Private => "Private",
        Privacy::Secret => "Secret",
    }
}

pub fn privacy_icon(p: Privacy) -> &'static str {
    match p {
        Privacy::Public => "eye",
        Privacy::Unlisted => "link",
        Privacy::Readonly => "file",
        Privacy::Private => "key-round",
        Privacy::Secret => "eye-off",
    }
}

/// A Unix time as "2026-11-09 14:03 UTC".
pub fn date(ts: i64) -> String {
    let format = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute] UTC");
    time::OffsetDateTime::from_unix_timestamp(ts).ok().and_then(|t| t.format(format).ok()).unwrap_or_default()
}

/// An RFC 3339 UTC timestamp for a `<time datetime>` attribute.
pub fn iso(ts: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_default()
}

/// How far `ts` is from `now`, in calm units without seconds: "in 3 h 2 min", "5 min ago". The
/// same rules are in `assets/js/paste.js`, which keeps the text fresh; keep the two in step.
pub fn relative(now: i64, ts: i64) -> String {
    let delta = ts - now;
    let secs = delta.unsigned_abs();
    if secs < 60 {
        return if delta >= 0 { "in less than a minute".into() } else { "just now".into() };
    }
    let minutes = secs / 60;
    let (hours, days) = (minutes / 60, minutes / 1440);
    let amount = if minutes < 60 {
        format!("{minutes} min")
    } else if hours < 24 {
        with_rest(hours, "h", minutes % 60, "min")
    } else if days < 30 {
        with_rest(days, "d", hours % 24, "h")
    } else if days < 365 {
        format!("{days} d")
    } else {
        with_rest(days / 365, "y", days % 365, "d")
    };
    if delta >= 0 { format!("in {amount}") } else { format!("{amount} ago") }
}

/// A moment shown as a `<time>` whose text `paste.js` keeps fresh.
pub struct TimeView {
    pub iso: String,
    /// The absolute time, for the tooltip.
    pub title: String,
    pub text: String,
    /// "expires" reads "Expired" once past; "ago" reads "5 min ago".
    pub kind: &'static str,
}

impl TimeView {
    pub fn new(ts: i64, now: i64, kind: &'static str) -> Self {
        let text = match kind {
            "expires" if ts <= now => "Expired".to_owned(),
            // Another clock may run ahead; a past event is never shown as in the future.
            "ago" => relative(now, ts.min(now - 1)),
            _ => relative(now, ts),
        };
        Self { iso: iso(ts), title: date(ts), text, kind }
    }

    /// An expiry: "in 3 h", "Expired", or "Never" when there is none.
    pub fn expiry(ts: Option<i64>, now: i64) -> Option<Self> {
        ts.map(|t| Self::new(t, now, "expires"))
    }
}

fn with_rest(big: u64, big_unit: &str, small: u64, small_unit: &str) -> String {
    if small == 0 { format!("{big} {big_unit}") } else { format!("{big} {big_unit} {small} {small_unit}") }
}

/// A byte count in binary units, e.g. "1.5 MiB".
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// The copy and check icons a copy button flips between.
pub fn copy_icons() -> String {
    format!("{}{}", icon("copy", IconSize::Row), icon("check", IconSize::Row))
}

/// A paste's full address on the public origin, and on the short host when one is configured.
pub fn paste_urls(st: &AppState, words: &str) -> (String, Option<String>) {
    let short = st.cfg.app.short_url.as_deref().map(|s| format!("{}/{words}", s.trim_end_matches('/')));
    (format!("{}/{words}", st.dep.origin), short)
}

/// Paste words from a path segment; anything else is simply not found.
pub fn paste_id(words: &str) -> Result<crate::domain::words::PasteId, Error> {
    crate::domain::words::parse(words).map_err(|_| Error::NotFound)
}
