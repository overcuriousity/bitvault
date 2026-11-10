use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use askama::Template;
use axum::Form as UrlForm;
use axum::Router;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use futures_util::{StreamExt, TryStreamExt, stream};
use multer::{Field, Multipart};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::admin::MaybeAdmin;
use super::multipart::{Guarded, too_large};
use super::{DeletedQuery, Extras, page_with};
use crate::assets::Assets;
use crate::config::{AppConfig, Config};
use crate::domain::crypto::{self, SALT_LEN};
use crate::domain::expiry::{self, Expiry};
use crate::domain::files::Staging;
use crate::domain::paste::{self, NewPaste, SecretParts};
use crate::domain::{self, Privacy, grant, highlight, words};
use crate::error::Error;
use crate::ratelimit::{self, RateLimiter};
use crate::security::ClientIp;
use crate::state::AppState;

const MIB: u64 = 1 << 20;
/// The syntax form value for detection from the first line, stored as no syntax.
const AUTO: &str = "auto";
/// Each text field of the create form, and the text of an API create.
pub(crate) const TEXT_LIMIT: usize = paste::TEXT_LIMIT;
const SECRET_IN_BROWSER: &str = "Secret pastes are encrypted in the browser. Create them on the web page instead.";
const SECRET_NEEDS_HTTPS: &str = "Secret pastes need https.";
// A secret paste's content container holds JSON of up to TEXT_LIMIT of text, which escaping can
// grow sixfold (a control character becomes \u00XX), plus 64 KiB of file names and the container
// overhead.
const CONTAINER_LIMIT: usize = crypto::browser_container_max_len(6 * TEXT_LIMIT as u64 + (64 << 10)) as usize;

/// A select option as (value, label, selected).
type Choice = (&'static str, &'static str, bool);

#[derive(Template)]
#[template(path = "home.html")]
struct Home {
    /// Privacy choices by group label, empty groups left out.
    privacy_groups: Vec<(&'static str, Vec<Choice>)>,
    expiry_options: Vec<(&'static str, String, bool)>,
    syntax_options: Vec<(String, String, bool)>,
    default_burn: u32,
    /// Whether Secret is offered, and with it its browser-only password field.
    secret: bool,
    editable: bool,
    uploader_password: bool,
    /// Total limit for the files of a paste, which `create.js` checks before uploading.
    max_file_mb: u64,
    /// Per-file plaintext limit for secret pastes, which `create.js` enforces before encrypting.
    max_secret_mb: u64,
    words_src: String,
    help_icon: String,
    /// The options' one-line summary as rendered; `create.js` keeps it in sync.
    summary: String,
    create_icon: String,
    open_icon: String,
    deleted: Option<String>,
}

const PRIVACY_GROUPS: [(&str, &[Privacy]); 3] = [
    ("No password", &[Privacy::Public, Privacy::Unlisted]),
    ("Password", &[Privacy::Readonly, Privacy::Private]),
    ("Encrypted in your browser", &[Privacy::Secret]),
];

fn sentence_case(s: &str) -> String {
    let mut chars = s.chars();
    chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

/// The same line `create.js` builds from the live choices, e.g. "Unlisted · 24 hours".
fn options_summary(privacy: &str, expiry: &str, burn: u32) -> String {
    let mut parts = vec![privacy.to_owned(), expiry.to_owned()];
    parts.retain(|p| !p.is_empty());
    match burn {
        0 => {}
        1 => parts.push("Burns after 1 read".to_owned()),
        n => parts.push(format!("Burns after {n} reads")),
    }
    parts.join(" · ")
}

#[derive(Deserialize)]
struct OpenForm {
    words: String,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(index)).route("/open", post(open))
}

/// `POST /`, for the upload group: large bodies, a long timeout and the create rate limit.
pub fn upload_routes() -> Router<AppState> {
    Router::new().route("/", post(create).layer(ratelimit::layer(Arc::new(RateLimiter::new(30, 10)))))
}

async fn index(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    Query(q): Query<DeletedQuery>,
) -> Result<Html<String>, Error> {
    let app = &st.cfg.app;
    let syntax_options = syntax_options(app, if app.highlight { None } else { Some(highlight::PLAIN) });
    let privacy_groups: Vec<_> = PRIVACY_GROUPS
        .iter()
        .map(|(group, levels)| {
            let offered = levels.iter().filter(|p| st.cfg.offers(**p));
            let options = offered.map(|p| (p.as_str(), super::privacy_label(*p), p.as_str() == app.default_privacy));
            (*group, options.collect::<Vec<_>>())
        })
        .filter(|(_, options)| !options.is_empty())
        .collect();
    let expiry_options: Vec<_> = Expiry::ALL
        .into_iter()
        .filter(|e| expiry::allowed(app, *e))
        .map(|e| (e.as_str(), sentence_case(e.label()), e.as_str() == app.default_expiry))
        .collect();
    let privacy = privacy_groups.iter().flat_map(|(_, o)| o).find(|o| o.2).map_or("", |o| o.1);
    let expiry_label = expiry_options.iter().find(|o| o.2).map_or("", |o| o.1.as_str());
    let summary = options_summary(privacy, expiry_label, app.default_burn_after);
    let home = Home {
        privacy_groups,
        expiry_options,
        syntax_options,
        default_burn: app.default_burn_after,
        secret: st.cfg.offers(Privacy::Secret),
        editable: app.editable,
        uploader_password: app.uploader_password.is_some(),
        max_file_mb: app.max_file_mb,
        max_secret_mb: app.max_secret_file_mb,
        words_src: Assets::url("bip39-english.txt"),
        help_icon: super::icon("circle-question-mark", super::IconSize::Row),
        summary,
        create_icon: super::icon("plus", super::IconSize::Tool),
        open_icon: super::icon("arrow-right", super::IconSize::Tool),
        deleted: q.notice().map(|n| super::escape_text(&n)),
    };
    let body = home.render().map_err(Error::internal)?;
    let extras = Extras { js: vec![Assets::url("js/create.js")], ..Extras::default() };
    page_with(&st, admin, "new", "New paste", body, extras)
}

/// `POST /open`: finds a paste by its words. htmx follows `HX-Redirect`; without it, a plain redirect.
async fn open(
    State(st): State<AppState>,
    headers: HeaderMap,
    UrlForm(form): UrlForm<OpenForm>,
) -> Result<Response, Error> {
    let id = words::parse_typed(&form.words)?;
    if !exists(&st, id, domain::now()).await? {
        return Err(invalid("No paste has these words. Check them and try again."));
    }
    Ok(go_to(&format!("/{}", id.words()), headers.contains_key("hx-request")))
}

/// Whether a paste has this address now.
async fn exists(st: &AppState, id: words::PasteId, now: i64) -> Result<bool, Error> {
    match paste::meta(st, id, now).await {
        Ok(_) => Ok(true),
        Err(Error::NotFound) => Ok(false),
        Err(e) => Err(e),
    }
}

/// The uploader password, when one is configured, must arrive before any file.
struct Gate<'a> {
    expected: Option<&'a str>,
    passed: bool,
    /// The failed-attempt limiter and the caller's address, when known.
    attempts: Option<(&'a RateLimiter, IpAddr)>,
}

impl<'a> Gate<'a> {
    fn new(st: &'a AppState, ip: Option<IpAddr>, passed: bool) -> Self {
        Self { expected: st.cfg.app.uploader_password.as_deref(), passed, attempts: ip.map(|ip| (&*st.failures, ip)) }
    }

    /// A wrong password counts as a failed attempt, like a wrong paste password: the token is
    /// taken before the comparison and given back when the password is right.
    fn check(&mut self, given: &[u8]) -> Result<(), Error> {
        let Some(expected) = self.expected else { return Ok(()) };
        if let Some((failures, ip)) = self.attempts {
            failures.take(ip)?;
        }
        // Both sides in NFC, like every other password; bytes that are not UTF-8 are compared as sent.
        let given = std::str::from_utf8(given).map_or_else(|_| Zeroizing::new(given.to_vec()), crypto::password_bytes);
        // Hashing first makes the comparison independent of both lengths.
        if bool::from(Sha256::digest(&*given).ct_eq(&Sha256::digest(&*crypto::password_bytes(expected)))) {
            self.passed = true;
            if let Some((failures, ip)) = self.attempts {
                failures.refund(ip);
            }
            Ok(())
        } else {
            Err(Error::UploaderPassword)
        }
    }

    fn require(&self) -> Result<(), Error> {
        if self.expected.is_none() || self.passed { Ok(()) } else { Err(Error::UploaderPassword) }
    }
}

/// Checks an uploader password given up front (the API's header) against the configured one.
pub(crate) fn check_uploader(st: &AppState, ip: Option<IpAddr>, given: Option<&[u8]>) -> Result<(), Error> {
    let mut gate = Gate::new(st, ip, false);
    if let Some(given) = given {
        gate.check(given)?;
    }
    gate.require()
}

/// Where the create form and the API's multipart create differ.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CreateRules {
    /// The uploader password was already checked, from the API's header.
    pub uploader_checked: bool,
    /// Only the browser can encrypt a secret paste, so the API refuses them.
    pub allow_secret: bool,
    /// `editable` when the request leaves it out: the server setting for the API, and false for
    /// the web form, whose unchecked box sends nothing.
    pub default_editable: bool,
}

impl CreateRules {
    fn allows(self, cfg: &Config, privacy: Privacy) -> Result<(), Error> {
        match privacy {
            Privacy::Secret if cfg.insecure_http => Err(invalid(SECRET_NEEDS_HTTPS)),
            Privacy::Secret if !self.allow_secret => Err(invalid(SECRET_IN_BROWSER)),
            _ => Ok(()),
        }
    }
}

/// A create request's fields, from the form or the API, before defaults are applied.
#[derive(Default)]
pub(crate) struct Form {
    pub content: String,
    pub privacy: Option<Privacy>,
    pub expiry: Option<Expiry>,
    pub burn_after_reads: Option<u32>,
    pub syntax: Option<String>,
    pub editable: Option<bool>,
    pub password: Option<String>,
    pub content_container: Option<Vec<u8>>,
    pub verifier_salt: Option<[u8; SALT_LEN]>,
    pub verifier: Option<[u8; 32]>,
    /// `intent=create`: store the text even when it reads as the words of an existing paste.
    pub create_only: bool,
}

fn invalid(msg: &str) -> Error {
    Error::Invalid(msg.to_owned())
}

fn multipart_error(e: &multer::Error) -> Error {
    if too_large(e) { Error::TooLarge } else { invalid("The form could not be read. Reload the page and try again.") }
}

async fn read_field(mut field: Field<'static>, limit: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(|e| multipart_error(&e))? {
        if out.len() + chunk.len() > limit {
            return Err(Error::TooLarge);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn text(value: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(value).map_err(|_| invalid("The text is not valid UTF-8. Save it as UTF-8 and try again."))
}

fn hex_array<const N: usize>(value: &[u8]) -> Result<[u8; N], Error> {
    hex::decode(value.trim_ascii())
        .ok()
        .and_then(|v| <[u8; N]>::try_from(v).ok())
        .ok_or_else(|| invalid("The browser sent an incomplete secret paste. Reload the page and try again."))
}

pub(crate) fn parse_privacy(value: &str) -> Result<Privacy, Error> {
    Privacy::parse(value.trim()).ok_or_else(|| invalid("Choose a privacy level from the list."))
}

pub(crate) fn parse_expiry(value: &str) -> Result<Expiry, Error> {
    Expiry::parse(value.trim()).ok_or_else(|| invalid("Choose an expiry from the list."))
}

fn default_privacy(st: &AppState) -> Result<Privacy, Error> {
    Privacy::parse(&st.cfg.app.default_privacy).ok_or_else(|| Error::internal("default_privacy is not a privacy level"))
}

/// `auto` (or nothing) leaves the syntax to detection when the paste is shown; `plain` and the
/// language tokens are stored as given.
pub(crate) fn parse_syntax(value: &str) -> Result<Option<String>, Error> {
    let value = value.trim();
    if value.is_empty() || value == AUTO {
        return Ok(None);
    }
    if value == highlight::PLAIN || highlight::languages().iter().any(|(token, _)| token == value) {
        Ok(Some(value.to_owned()))
    } else {
        Err(invalid("Choose a syntax from the list."))
    }
}

/// The syntax choices as (value, label, selected), with `chosen` selected (`None` is Automatic).
/// Automatic and the languages are offered while highlighting is on, and whenever already chosen.
pub(crate) fn syntax_options(app: &AppConfig, chosen: Option<&str>) -> Vec<(String, String, bool)> {
    let mut options = Vec::new();
    if app.highlight || chosen.is_none() {
        options.push((AUTO.to_owned(), "Automatic".to_owned(), chosen.is_none()));
    }
    options.push((highlight::PLAIN.to_owned(), "Plain".to_owned(), chosen == Some(highlight::PLAIN)));
    let chosen_language = chosen.is_some_and(|c| c != highlight::PLAIN);
    if app.highlight || chosen_language {
        options.extend(highlight::languages().iter().map(|(t, n)| (t.clone(), n.clone(), chosen == Some(t.as_str()))));
    }
    options
}

impl Form {
    fn set(&mut self, name: &str, value: Vec<u8>, staged: bool, offered: &[String]) -> Result<(), Error> {
        match name {
            "content" => self.content = text(value)?,
            "privacy" => {
                let privacy = parse_privacy(&text(value)?)?;
                // Checked here as well as on create, so files never stream in for a refused level.
                if !offered.iter().any(|l| l == privacy.as_str()) {
                    return Err(invalid("That privacy level is not offered here. Choose another one."));
                }
                // Files are stored the way the level needs while they stream, so the level
                // cannot change once one has arrived.
                if staged && self.privacy != Some(privacy) {
                    return Err(invalid("Choose the privacy level before adding files."));
                }
                self.privacy = Some(privacy);
            }
            "expiry" => self.expiry = Some(parse_expiry(&text(value)?)?),
            "burn_after_reads" => {
                let v = text(value)?;
                if !v.trim().is_empty() {
                    self.burn_after_reads = Some(
                        v.trim().parse().map_err(|_| invalid("Enter a whole number of reads, or 0 for no limit."))?,
                    );
                }
            }
            "syntax" => self.syntax = parse_syntax(&text(value)?)?,
            "editable" => self.editable = Some(matches!(text(value)?.trim(), "on" | "true" | "1")),
            "password" => self.password = Some(text(value)?).filter(|p| !p.is_empty()),
            "content_container" => {
                crypto::check_browser_container(&value)?;
                self.content_container = Some(value);
            }
            "verifier_salt" => self.verifier_salt = Some(hex_array(&value)?),
            "verifier" => self.verifier = Some(hex_array(&value)?),
            "intent" => self.create_only = text(value)?.trim() == "create",
            _ => {}
        }
        Ok(())
    }

    /// The paste to create, with the configured defaults for what was left out.
    pub(crate) fn into_new(self, st: &AppState, rules: CreateRules) -> Result<NewPaste, Error> {
        let app = &st.cfg.app;
        let privacy = match self.privacy {
            Some(p) => p,
            None => default_privacy(st)?,
        };
        rules.allows(&st.cfg, privacy)?;
        let expiry = match self.expiry {
            Some(e) => e,
            None => Expiry::parse(&app.default_expiry).ok_or_else(|| Error::internal("default_expiry is invalid"))?,
        };
        let secret = match (privacy, self.content_container, self.verifier_salt, self.verifier) {
            (Privacy::Secret, Some(container), Some(verifier_salt), Some(verifier)) => {
                Some(SecretParts { container, verifier_salt, verifier })
            }
            _ => None,
        };
        Ok(NewPaste {
            content: self.content,
            privacy,
            expiry,
            burn_after_reads: self.burn_after_reads.unwrap_or(app.default_burn_after),
            syntax: self.syntax,
            editable: self.editable.unwrap_or(rules.default_editable),
            password: self.password,
            secret,
        })
    }
}

/// `POST /`: to the new paste, with the creator cookie that shows it once without counting a read.
/// A fetch or htmx create (`HX-Request`) gets 200 with `HX-Redirect` instead of a 303: fetch
/// would follow the 303 itself, using up the cookie on a response the browser never shows.
///
/// The box is also how a paste is opened: text alone that reads as the words of a paste that
/// exists goes to that paste instead, unless the form says `intent=create`. Such a lookup draws on
/// the same budget as `/open`, so the box is no faster way to guess addresses.
async fn create(State(st): State<AppState>, req: Request) -> Result<Response, Error> {
    let htmx = req.headers().contains_key("hx-request");
    let ip = req.extensions().get::<ClientIp>().map(|c| c.0);
    let rules = CreateRules { uploader_checked: false, allow_secret: true, default_editable: false };
    let (form, staging, gate) = read_form(&st, req, rules).await?;
    let now = domain::now();
    if staging.is_none()
        && let Some(id) = existing_paste(&st, &form, ip, now).await?
    {
        return Ok(go_to(&format!("/{}", id.words()), htmx));
    }
    gate?;
    let id = paste::create(&st, form.into_new(&st, rules)?, staging, now).await?;
    let words = id.words();
    let token = grant::issue_creator(&st.grant_key, id, now);
    let mut res = go_to(&format!("/{words}"), htmx);
    res.headers_mut().insert(header::SET_COOKIE, super::paste::created_cookie(&st, &words, &token, grant::TTL_SECS)?);
    Ok(res)
}

/// A fetch or htmx request follows `HX-Redirect`; a plain form post a 303.
fn go_to(target: &str, htmx: bool) -> Response {
    if htmx {
        (StatusCode::OK, [("hx-redirect", target.to_owned())]).into_response()
    } else {
        Redirect::to(target).into_response()
    }
}

/// The paste a box of plain text names, when the text is three paste words and that paste exists.
/// A lookup that finds nothing keeps its token, like a miss on `/open`.
async fn existing_paste(
    st: &AppState,
    form: &Form,
    ip: Option<std::net::IpAddr>,
    now: i64,
) -> Result<Option<words::PasteId>, Error> {
    // Three words of at most eight letters, with room for separators and spaces around them.
    if form.create_only || form.content_container.is_some() || form.content.len() > 64 {
        return Ok(None);
    }
    let Ok(id) = words::parse_typed(&form.content) else { return Ok(None) };
    if let Some(ip) = ip {
        st.lookups.take(ip)?;
    }
    let found = exists(st, id, now).await;
    if let (Some(ip), false) = (ip, matches!(found, Ok(false))) {
        st.lookups.refund(ip);
    }
    Ok(found?.then_some(id))
}

/// Reads a multipart create in order, streaming each file into a staging directory (encrypted
/// for private pastes) and keeping only the small fields in memory. Fields that decide how files
/// are stored (`uploader_password`, `privacy`) must come before the first file.
pub(crate) async fn read_multipart(
    st: &AppState,
    req: Request,
    rules: CreateRules,
) -> Result<(NewPaste, Option<Staging>), Error> {
    let (form, staging, gate) = read_form(st, req, rules).await?;
    gate?;
    Ok((form.into_new(st, rules)?, staging))
}

/// [`read_multipart`] without its last two steps, so the web form can open an existing paste
/// before asking for the uploader password. A file still needs the password before it streams.
/// The third value says whether the uploader password was given.
async fn read_form(
    st: &AppState,
    req: Request,
    rules: CreateRules,
) -> Result<(Form, Option<Staging>, Result<(), Error>), Error> {
    let ip = req.extensions().get::<ClientIp>().map(|c| c.0);
    let boundary = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|ct| multer::parse_boundary(ct).ok())
        .ok_or_else(|| invalid("Send the form as multipart/form-data."))?;
    let body = Guarded::new(req.into_body().into_data_stream(), &boundary);
    let mut multipart = Multipart::new(body, boundary);
    let app = &st.cfg.app;
    let budget = app.max_file_mb.saturating_mul(MIB);
    // The browser limits plaintext; the server sees the container, which is slightly larger.
    let secret_limit = crypto::browser_container_max_len(app.max_secret_file_mb.saturating_mul(MIB));
    let mut gate = Gate::new(st, ip, rules.uploader_checked);
    let mut form = Form::default();
    let mut staging: Option<Staging> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| multipart_error(&e))? {
        let name = field.name().unwrap_or_default().to_owned();
        if name != "file" {
            let limit = if name == "content_container" { CONTAINER_LIMIT } else { TEXT_LIMIT };
            let value = read_field(field, limit).await?;
            if name == "uploader_password" {
                gate.check(&value)?;
            } else {
                form.set(&name, value, staging.is_some(), &app.privacy_levels)?;
                if let Some(privacy) = form.privacy {
                    rules.allows(&st.cfg, privacy)?;
                }
            }
            continue;
        }
        gate.require()?;
        let privacy = match form.privacy {
            Some(p) => p,
            None => *form.privacy.insert(default_privacy(st)?),
        };
        rules.allows(&st.cfg, privacy)?;
        let filename = field.file_name().unwrap_or_default().to_owned();
        let claimed_mime = field.content_type().map(ToString::to_string).unwrap_or_default();
        // Browsers send an empty, unnamed part when no file was chosen, so a part is only
        // staged once it has a first byte.
        let mut field = field;
        let first = loop {
            match field.chunk().await.map_err(|e| multipart_error(&e))? {
                Some(chunk) if chunk.is_empty() => {}
                other => break other,
            }
        };
        let first = match first {
            Some(chunk) => chunk,
            None if filename.is_empty() && privacy != Privacy::Secret => continue,
            None => bytes::Bytes::new(),
        };
        let staged = match &mut staging {
            Some(s) => s,
            None if privacy == Privacy::Private => staging.insert(Staging::new_private(&st.files_dir)?),
            None => staging.insert(Staging::new(&st.files_dir)?),
        };
        let remaining = budget.saturating_sub(staged.total_size());
        // The body limit surfaces as a stream error; remember it so it is reported as too large.
        let over = AtomicBool::new(false);
        let body = Box::pin(stream::iter([Ok(first)]).chain(field).inspect_err(|e| {
            if too_large(e) {
                over.store(true, Ordering::Relaxed);
            }
        }));
        let added = if privacy == Privacy::Secret {
            staged.add_container(body, remaining.min(secret_limit)).await
        } else {
            staged.add(&filename, &claimed_mime, body, remaining).await
        };
        match added {
            Err(_) if over.load(Ordering::Relaxed) => return Err(Error::TooLarge),
            other => other?,
        };
    }
    Ok((form, staging, gate.require()))
}
