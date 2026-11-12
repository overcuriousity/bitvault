//! The paste page, unlock, raw text, edit and delete.

use std::sync::{Arc, LazyLock};

use askama::Template;
use axum::Form;
use axum::Router;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use tokio::sync::Semaphore;

use super::admin::MaybeAdmin;
use super::files::{GrantQuery, inline_image};
use super::{
    Extras, IconSize, TimeView, copy_icons, date, escape_text, icon, page_with, paste_id, paste_urls, render, size,
};
use crate::assets::Assets;
use crate::domain::paste::{self, Access, Body, DeleteAuth, Opened, Paste};
use crate::domain::words::PasteId;
use crate::domain::{self, Kind, Privacy, grant, highlight, qr};
use crate::error::Error;
use crate::security::{BaseUrl, ClientIp};
use crate::state::AppState;

/// Content above this size is shown plain: syntect's fancy-regex can backtrack badly on large
/// or crafted input, which would make every view of such a paste expensive.
pub const HIGHLIGHT_LIMIT: usize = 128 * 1024;
/// Highlighting runs on the blocking pool, at most this many at once, so slow input can neither
/// stall the async workers nor take over the pool.
const HIGHLIGHT_PERMITS: usize = 2;
static HIGHLIGHT_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(HIGHLIGHT_PERMITS)));
const HTML: &str = "text/html; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";
const OCTETS: &str = "application/octet-stream";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/{words}", get(view))
        .route("/{words}/unlock", post(unlock))
        .route("/{words}/raw", get(raw))
        .route("/{words}/edit", get(edit_form))
        .route("/{words}/delete", post(delete))
}

/// `POST /{words}/edit`, for the edit group: its body may carry a whole paste's text, which form
/// encoding can grow up to threefold.
pub fn edit_routes() -> Router<AppState> {
    Router::new().route("/{words}/edit", post(edit))
}

/// A page's delete form, and how it proves the right to delete. No level asks for a password
/// here: whoever opened the paste has already given it.
pub struct DeleteView {
    pub action: String,
    /// The grant from unlocking a private paste, sent along as the proof.
    pub grant: Option<String>,
    /// Hex verifier salt of a secret paste. The form stays hidden until `secret.js` has opened the
    /// paste, and then derives the verifier from the password typed to open it.
    pub salt: String,
}

impl DeleteView {
    /// `None` when this viewer cannot delete: a read-only paste (only the admin deletes it) and
    /// a private one that has not been unlocked.
    fn new(p: &Paste, admin: bool, grant: Option<&str>) -> Option<Self> {
        let view = |grant: Option<&str>, salt: String| Self {
            action: format!("/{}/delete", p.id.words()),
            grant: grant.map(str::to_owned),
            salt,
        };
        match p.privacy {
            _ if admin => Some(view(None, String::new())),
            Privacy::Public | Privacy::Unlisted => Some(view(None, String::new())),
            Privacy::Readonly => None,
            Privacy::Private => grant.map(|g| view(Some(g), String::new())),
            Privacy::Secret => Some(view(None, p.verifier_salt.map(hex::encode).unwrap_or_default())),
        }
    }

    fn secret(&self) -> bool {
        !self.salt.is_empty()
    }
}

struct FileView {
    position: u32,
    name: String,
    size: String,
    href: String,
    /// The full address, for the copy button.
    url: String,
    preview: bool,
}

/// One row of the facts list: some text, then optionally a time.
struct Fact {
    term: &'static str,
    text: String,
    time: Option<TimeView>,
}

impl Fact {
    fn text(term: &'static str, text: String) -> Self {
        Self { term, text, time: None }
    }

    fn time(term: &'static str, text: &str, ts: i64, now: i64, kind: &'static str) -> Self {
        Self { term, text: text.to_owned(), time: Some(TimeView::new(ts, now, kind)) }
    }
}

/// What a paste page shows as its content.
enum Shown {
    /// Escaped or highlighted markup, and whether it is highlighted.
    Text(String, bool),
    /// A URL paste's target.
    Url(String),
    /// A secret paste's shell, which `secret.js` fills.
    Secret,
    /// A private paste seen without its password: neither its text nor its files.
    Sealed,
}

#[derive(Template)]
#[template(path = "paste.html")]
struct PasteView {
    /// The creator view, right after a web create.
    created: bool,
    word_list: Vec<String>,
    full_url: String,
    short_url: Option<String>,
    facts: Vec<Fact>,
    burned: bool,
    secret: bool,
    /// The paste has a burn limit, so `secret.js` fetches its ciphertext only when asked to open it.
    burns: bool,
    /// The values `secret.js` lists for decrypting a secret paste elsewhere, as (label, part).
    cipher_rows: [(&'static str, &'static str); 5],
    /// A secret paste over plain HTTP, where the browser cannot decrypt it: a notice instead of
    /// the open form, and no secret.js.
    https_only: bool,
    sealed: bool,
    /// Where a sealed paste's password form posts.
    unlock_action: String,
    raw_href: Option<String>,
    qr: Option<String>,
    translate: Option<String>,
    edit_href: Option<String>,
    delete: Option<DeleteView>,
    /// Escaped or highlighted markup; `None` for a secret paste, which `secret.js` fills.
    content: Option<String>,
    highlighted: bool,
    /// Whether the page has text a Copy text button can copy.
    copy_text: bool,
    /// A URL paste's target, shown with a link to it.
    target: Option<String>,
    files: Vec<FileView>,
    zip_href: Option<String>,
}

impl PasteView {
    fn icon(&self, name: &str) -> String {
        icon(name, IconSize::Tool)
    }

    fn row_icon(&self, name: &str) -> String {
        icon(name, IconSize::Row)
    }

    fn copy_icons(&self) -> String {
        copy_icons()
    }
}

#[derive(Template)]
#[template(path = "unlock.html")]
struct Unlock {
    words: String,
    notice: Option<String>,
}

#[derive(Template)]
#[template(path = "edit.html")]
struct EditPage {
    words: String,
    content: String,
    syntax_options: Vec<(String, String, bool)>,
    /// The grant from unlocking a private paste, which the save sends back as its proof.
    grant: Option<String>,
    notice: Option<String>,
}

/// Highlighted markup when highlighting is on, the text is small enough and the syntax is known
/// or, for an automatic one (`None`), detected from the first line; escaped plain text otherwise.
/// Either way each line is wrapped in `<span class="line">`. The language is looked up first,
/// so plain pastes never wait for a highlight slot.
async fn content_html(st: &AppState, text: &str, syntax: Option<&str>) -> Result<(String, bool), Error> {
    let found =
        (st.cfg.app.highlight && text.len() <= HIGHLIGHT_LIMIT).then(|| highlight::resolve(text, syntax)).flatten();
    if let Some(found) = found {
        // The permit moves into the closure, so it is held until the work ends even if the
        // request is dropped.
        let permit = Arc::clone(&HIGHLIGHT_SLOTS).acquire_owned().await.map_err(Error::internal)?;
        let owned = text.to_owned();
        let html = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            highlight::render_with(&owned, found)
        })
        .await
        .map_err(Error::internal)?;
        if let Some(html) = html {
            return Ok((html, true));
        }
    }
    Ok((highlight::wrap_lines(&escape_text(text)), false))
}

fn reads(n: u32) -> String {
    if n == 1 { "1 read".to_owned() } else { format!("{n} reads") }
}

/// The page for a paste whose content (if any) has been read and rendered by [`content_html`].
/// `grant` is set after an unlock and on the burning read; it is added to the links that need it.
/// `created` marks the creator view.
fn paste_view(
    st: &AppState,
    admin: bool,
    base: &BaseUrl,
    p: &Paste,
    shown: Shown,
    grant: Option<&str>,
    created: bool,
) -> PasteView {
    let app = &st.cfg.app;
    let words = p.id.words();
    let burned = p.burned_at.is_some();
    let secret = p.privacy == Privacy::Secret;
    let sealed = matches!(shown, Shown::Sealed);
    let files_g = grant.map(|g| format!("?g={g}")).unwrap_or_default();
    // Raw and edit only take a grant from an unlock; a burned paste has neither.
    let read_g = if p.privacy == Privacy::Private { files_g.clone() } else { String::new() };
    let (full, short_url) = paste_urls(st, base, &words);
    let raw_href = (!secret && !sealed).then(|| format!("/{words}/raw{read_g}"));
    let now = domain::now();
    let mut facts = vec![Fact::text("Created", date(p.created_at))];
    facts.push(match p.expires_at {
        Some(ts) => Fact::time("Expires", "", ts, now, "expires"),
        None => Fact::text("Expires", "Never".to_owned()),
    });
    if p.burn_after_reads > 0 {
        facts.push(Fact::text("Burns after", reads(p.burn_after_reads)));
    }
    if app.read_stats {
        facts.push(match p.last_read_at {
            Some(ts) => Fact::time("Reads", &format!("{}, last ", p.read_count), ts, now, "ago"),
            None => Fact::text("Reads", p.read_count.to_string()),
        });
    }
    let translate = app.translate_url.as_deref().filter(|_| {
        matches!(p.privacy, Privacy::Public | Privacy::Unlisted | Privacy::Readonly)
            && p.kind == Kind::Text
            // The translator fetches the raw text, which counts as a read.
            && p.burn_after_reads == 0
            && !burned
    });
    let translate = translate.map(|base| {
        let raw: String = url::form_urlencoded::byte_serialize(format!("{full}/raw").as_bytes()).collect();
        let sep = if base.contains('?') { '&' } else { '?' };
        format!("{base}{sep}from={raw}")
    });
    let editable = paste::editable(st, p) && !burned;
    let edit_href =
        editable.then(|| format!("/{words}/edit{read_g}")).filter(|_| p.privacy != Privacy::Private || grant.is_some());
    let (content, highlighted, target) = match shown {
        Shown::Text(html, hl) => (Some(html), hl, None),
        Shown::Url(target) => (None, false, Some(target)),
        Shown::Secret | Shown::Sealed => (None, false, None),
    };
    let copy_text = !secret && content.as_ref().is_some_and(|c| !c.is_empty());
    let files = p
        .files
        .iter()
        .filter(|_| !sealed)
        .map(|f| {
            let href = format!("/{words}/file/{}{files_g}", f.position);
            FileView {
                position: f.position,
                name: f.name.clone(),
                size: if secret { String::new() } else { size(f.size) },
                url: format!("{}{href}", base.0),
                preview: !secret && inline_image(&f.mime),
                href,
            }
        })
        .collect::<Vec<_>>();
    PasteView {
        created,
        word_list: words.split('-').map(str::to_owned).collect(),
        short_url,
        facts,
        burned,
        secret,
        burns: p.burn_after_reads > 0,
        cipher_rows: [
            ("Iterations", "iterations"),
            ("Salt", "salt"),
            ("IV", "iv"),
            ("Associated data", "aad"),
            ("Tag", "tag"),
        ],
        https_only: secret && st.dep.plain_http,
        sealed,
        unlock_action: format!("/{words}/unlock"),
        raw_href,
        qr: if app.qr && !burned { qr::svg(&full).ok() } else { None },
        translate,
        edit_href,
        // A secret paste's delete needs secret.js, which plain HTTP does not load.
        delete: DeleteView::new(p, admin, grant).filter(|d| !burned && !(d.secret() && st.dep.plain_http)),
        content,
        highlighted,
        copy_text,
        target,
        zip_href: (!secret && !files.is_empty()).then(|| format!("/{words}/zip{files_g}")),
        files,
        full_url: full,
    }
}

fn render_paste(st: &AppState, admin: bool, view: &PasteView, words: &str) -> Result<Response, Error> {
    let body = render(view)?;
    let mut js = vec![Assets::url("js/paste.js")];
    if view.secret && !view.https_only {
        js.push(Assets::url("js/secret.js"));
    }
    let extras = Extras { css: vec![Assets::url("css/syntax.css")], js };
    Ok(no_store(page_with(st, admin, "", words, body, extras)?.into_response()))
}

/// The answer to a HEAD request on a route whose GET counts a read: the type and headers only,
/// without reading (and so without counting or burning) the paste.
pub fn head_only(content_type: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "no-store")]).into_response()
}

/// Pages that carry paste content (decrypted private text, burned pages) must not persist in
/// browser caches or history.
fn no_store(mut res: Response) -> Response {
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

async fn shown(st: &AppState, p: &Paste, body: &Body) -> Result<Shown, Error> {
    match body {
        Body::Text(t) => {
            let (html, highlighted) = content_html(st, t, p.syntax.as_deref()).await?;
            Ok(Shown::Text(html, highlighted))
        }
        Body::Url(target) => Ok(Shown::Url(target.clone())),
        Body::Cipher(_) => Err(Error::internal("a secret paste cannot be rendered on the server")),
    }
}

async fn render_opened(st: &AppState, admin: bool, base: &BaseUrl, opened: &Opened) -> Result<Response, Error> {
    let shown = shown(st, &opened.paste, &opened.body).await?;
    let view = paste_view(st, admin, base, &opened.paste, shown, opened.grant.as_deref(), false);
    render_paste(st, admin, &view, &opened.paste.id.words())
}

/// The page a web create lands on: the paste as a reader would see it, without counting a read.
async fn render_creator(st: &AppState, admin: bool, base: &BaseUrl, id: PasteId, now: i64) -> Result<Response, Error> {
    let (p, body) = paste::creator_view(st, id, now).await?;
    let shown = match &body {
        Some(body) => shown(st, &p, body).await?,
        None if p.privacy == Privacy::Secret => Shown::Secret,
        None => Shown::Sealed,
    };
    let view = paste_view(st, admin, base, &p, shown, None, true);
    render_paste(st, admin, &view, &id.words())
}

fn unlock_page(
    st: &AppState,
    admin: bool,
    words: String,
    notice: Option<String>,
    status: StatusCode,
) -> Result<Response, Error> {
    let title = words.clone();
    let body = render(&Unlock { words, notice })?;
    Ok((status, page_with(st, admin, "", &title, body, Extras::default())?).into_response())
}

/// The cookie that carries a creator token from `POST /` to the paste page it redirects to.
/// Unlike a query parameter, it is not in the address the creator might share.
pub(crate) const CREATED_COOKIE: &str = "bitvault-created";

/// `Set-Cookie` for the creator cookie, scoped to `/{words}`: `token` for `max_age` seconds, or
/// cleared with an empty token and 0.
pub(crate) fn created_cookie(st: &AppState, words: &str, token: &str, max_age: i64) -> Result<HeaderValue, Error> {
    let secure = if st.dep.secure { "; Secure" } else { "" };
    let cookie = format!("{CREATED_COOKIE}={token}; Path=/{words}; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}");
    HeaderValue::from_str(&cookie).map_err(Error::internal)
}

/// Every creator cookie value the request carries.
fn created_tokens(headers: &HeaderMap) -> Vec<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().strip_prefix(CREATED_COOKIE)?.strip_prefix('='))
        .collect()
}

/// `GET /{words}`: content for plaintext levels (a read), the unlock form for private (no
/// read), and an empty shell for secret, which the browser fills from `/raw`. A URL paste
/// shows its target with a link and never redirects: following it is the reader's choice, and
/// the instance is no open redirector. A valid creator cookie shows the creator view instead,
/// once: any creator cookie, valid or not, is cleared, and a token already redeemed is refused
/// even if the cookie is sent again.
async fn view(
    State(st): State<AppState>,
    viewer: Viewer,
    method: Method,
    Path(words): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let now = domain::now();
    let tokens = created_tokens(&headers);
    // A HEAD request must neither redeem nor clear the creator token the following GET needs.
    let head = method == Method::HEAD;
    let mut res = if !head && tokens.iter().any(|t| grant::redeem_creator(&st.grant_key, &st.redeemed, t, id, now)) {
        render_creator(&st, viewer.admin, &viewer.base, id, now).await?
    } else {
        ordinary_view(&st, &viewer, &method, id, now).await?
    };
    if !head && !tokens.is_empty() {
        res.headers_mut().append(header::SET_COOKIE, created_cookie(&st, &id.words(), "", 0)?);
    }
    Ok(res)
}

/// Who is looking at a paste page, and the origin its addresses start with.
struct Viewer {
    admin: bool,
    ip: std::net::IpAddr,
    base: BaseUrl,
}

impl FromRequestParts<AppState> for Viewer {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Error> {
        let Ok(MaybeAdmin(admin)) = MaybeAdmin::from_request_parts(parts, st).await;
        let ClientIp(ip) = ClientIp::from_request_parts(parts, st).await?;
        let base = BaseUrl::from_request_parts(parts, st).await?;
        Ok(Self { admin, ip, base })
    }
}

async fn ordinary_view(
    st: &AppState,
    viewer: &Viewer,
    method: &Method,
    id: PasteId,
    now: i64,
) -> Result<Response, Error> {
    let Viewer { admin, ip, ref base } = *viewer;
    let p = paste::meta(st, id, now).await?;
    match p.privacy {
        // Only the form: a private paste's file names and sizes are private as well.
        Privacy::Private => unlock_page(st, admin, id.words(), None, StatusCode::OK),
        Privacy::Secret => {
            let view = paste_view(st, admin, base, &p, Shown::Secret, None, false);
            render_paste(st, admin, &view, &id.words())
        }
        _ if *method == Method::HEAD => Ok(head_only(HTML)),
        _ => {
            let opened = paste::read(st, &p, Access::Anonymous, ip, now).await?;
            render_opened(st, admin, base, &opened).await
        }
    }
}

#[derive(Deserialize)]
struct PasswordForm {
    #[serde(default)]
    password: String,
}

/// `POST /{words}/unlock`: a private paste's content and grant links, or the form again.
async fn unlock(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    ClientIp(ip): ClientIp,
    base: BaseUrl,
    Path(words): Path<String>,
    Form(form): Form<PasswordForm>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let now = domain::now();
    let p = paste::meta(&st, id, now).await?;
    if p.privacy != Privacy::Private {
        return Ok(Redirect::to(&format!("/{}", id.words())).into_response());
    }
    if form.password.is_empty() {
        let notice = Some(Error::PasswordRequired.to_string());
        return unlock_page(&st, admin, id.words(), notice, StatusCode::UNPROCESSABLE_ENTITY);
    }
    match paste::read(&st, &p, Access::Password(form.password), ip, now).await {
        Ok(opened) => render_opened(&st, admin, &base, &opened).await,
        Err(e @ Error::WrongPassword) => {
            unlock_page(&st, admin, id.words(), Some(e.to_string()), StatusCode::UNPROCESSABLE_ENTITY)
        }
        Err(e @ Error::TooManyAttempts) => unlock_page(&st, admin, id.words(), Some(e.to_string()), e.status()),
        Err(e) => Err(e),
    }
}

/// `GET /{words}/raw`: the text, or a secret paste's container. Private needs `?g=` or
/// `X-Paste-Password`.
async fn raw(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    method: Method,
    Path(words): Path<String>,
    Query(q): Query<GrantQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let now = domain::now();
    let p = paste::meta(&st, id, now).await?;
    let access = match (p.privacy, q.g) {
        (Privacy::Private, Some(g)) => Access::Grant(g),
        (Privacy::Private, None) => {
            // As UTF-8, like the API: `to_str` would refuse every password beyond ASCII.
            let pw = headers
                .get(crate::api::PASSWORD_HEADER)
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .ok_or(Error::PasswordRequired)?;
            Access::Password(pw.to_owned())
        }
        _ => Access::Anonymous,
    };
    if method == Method::HEAD {
        return Ok(head_only(if p.privacy == Privacy::Secret { OCTETS } else { TEXT }));
    }
    let opened = paste::read(&st, &p, access, ip, now).await?;
    let (content_type, bytes) = match opened.body {
        Body::Text(t) | Body::Url(t) => (TEXT, t.into_bytes()),
        Body::Cipher(c) => (OCTETS, c),
    };
    let mut res = ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "no-store")], bytes).into_response();
    // On the burning read (and after a password unlock) the grant lets the reader fetch the files.
    if let Some(g) = opened.grant.as_deref().and_then(|g| HeaderValue::from_str(g).ok()) {
        res.headers_mut().insert("x-bitvault-grant", g);
    }
    Ok(res)
}

/// The edit pages exist only for pastes that can be edited now.
fn editable(st: &AppState, p: &Paste) -> Result<(), Error> {
    if paste::editable(st, p) { Ok(()) } else { Err(Error::NotFound) }
}

/// What the edit form holds: the text and syntax, and a private paste's grant.
struct Draft<'a> {
    content: String,
    syntax: Option<&'a str>,
    grant: Option<String>,
}

fn edit_page(
    st: &AppState,
    admin: bool,
    p: &Paste,
    draft: Draft<'_>,
    notice: Option<String>,
    status: StatusCode,
) -> Result<Response, Error> {
    let words = p.id.words();
    let view = EditPage {
        words: words.clone(),
        content: draft.content,
        syntax_options: super::home::syntax_options(&st.cfg.app, draft.syntax),
        grant: draft.grant,
        notice,
    };
    let body = render(&view)?;
    let page = page_with(st, admin, "", &format!("Edit {words}"), body, Extras::default())?;
    Ok(no_store((status, page).into_response()))
}

/// `GET /{words}/edit`: the form, prefilled. Showing the content counts as a read; a private
/// paste needs the grant from its unlocked page. A read that burns the paste leaves nothing to
/// save, so it shows the paste's page, as any other last read does.
async fn edit_form(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    ClientIp(ip): ClientIp,
    base: BaseUrl,
    method: Method,
    Path(words): Path<String>,
    Query(q): Query<GrantQuery>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let now = domain::now();
    let p = paste::meta(&st, id, now).await?;
    editable(&st, &p)?;
    let grant = q.g.filter(|_| p.privacy == Privacy::Private);
    let access = match (p.privacy, &grant) {
        (Privacy::Private, Some(g)) => Access::Grant(g.clone()),
        (Privacy::Private, None) => return Ok(Redirect::to(&format!("/{}", id.words())).into_response()),
        _ => Access::Anonymous,
    };
    if method == Method::HEAD {
        return Ok(head_only(HTML));
    }
    let opened = paste::read(&st, &p, access, ip, now).await?;
    if opened.paste.burned_at.is_some() {
        return render_opened(&st, admin, &base, &opened).await;
    }
    let content = match opened.body {
        Body::Text(t) | Body::Url(t) => t,
        Body::Cipher(_) => return Err(Error::NotFound),
    };
    let draft = Draft { content, syntax: opened.paste.syntax.as_deref(), grant };
    edit_page(&st, admin, &opened.paste, draft, None, StatusCode::OK)
}

#[derive(Deserialize)]
struct EditForm {
    #[serde(default)]
    content: String,
    #[serde(default)]
    syntax: String,
    /// The grant from unlocking a private paste.
    #[serde(default)]
    g: String,
}

/// `POST /{words}/edit`: saves and returns to the paste, or shows the form again with a notice.
/// A private paste is saved with the grant its unlocked page handed to the form.
async fn edit(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    ClientIp(ip): ClientIp,
    Path(words): Path<String>,
    Form(form): Form<EditForm>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let now = domain::now();
    let p = paste::meta(&st, id, now).await?;
    editable(&st, &p)?;
    let syntax = super::home::parse_syntax(&form.syntax)?;
    let grant = Some(form.g).filter(|g| !g.is_empty());
    let access = grant.clone().map_or(Access::Anonymous, Access::Grant);
    match paste::edit(&st, id, access, ip, form.content.clone(), syntax.clone(), now).await {
        Ok(()) => Ok(Redirect::to(&format!("/{}", id.words())).into_response()),
        // The text typed stays on the page, so it can be copied before opening the paste again.
        Err(e @ (Error::Forbidden | Error::GrantExpired | Error::Invalid(_))) => {
            let message = match &e {
                Error::Invalid(_) => e.to_string(),
                _ => "Open the paste with its password again, then change it.".to_owned(),
            };
            let draft = Draft { content: form.content, syntax: syntax.as_deref(), grant };
            edit_page(&st, admin, &p, draft, Some(message), e.status())
        }
        Err(e) => Err(e),
    }
}

#[derive(Deserialize)]
struct DeleteForm {
    /// The grant from unlocking a private paste.
    #[serde(default)]
    g: String,
    /// Hex `HMAC-SHA256(verifier key, "bitvault-delete")` from `secret.js`.
    #[serde(default)]
    verifier: String,
    /// "admin" returns to the admin table.
    #[serde(default)]
    next: String,
}

fn verifier(hex_value: &str) -> Result<[u8; 32], Error> {
    hex::decode(hex_value.trim()).ok().and_then(|v| <[u8; 32]>::try_from(v).ok()).ok_or_else(|| {
        Error::Invalid("The browser sent an incomplete delete request. Reload the page and try again.".into())
    })
}

/// `POST /{words}/delete`: deletes at once and returns to `/` with a notice. The admin needs no
/// proof; a private paste takes the grant from its unlocked page, a secret one its verifier.
async fn delete(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    ClientIp(ip): ClientIp,
    Path(words): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let now = domain::now();
    let by_verifier = !form.verifier.is_empty();
    let auth = if admin {
        DeleteAuth::Admin
    } else if by_verifier {
        DeleteAuth::Verifier(verifier(&form.verifier)?)
    } else if !form.g.is_empty() {
        DeleteAuth::Grant(form.g)
    } else {
        DeleteAuth::None
    };
    match paste::delete(&st, id, auth, ip, now).await {
        Ok(()) => {
            let back = if admin && form.next == "admin" { "/admin" } else { "/" };
            Ok(Redirect::to(&format!("{back}?deleted={}", id.words())).into_response())
        }
        // The grant ran out while the page stood open: the password opens the paste again.
        Err(e @ Error::GrantExpired) => {
            let notice = "Open the paste with its password again, then delete it.".to_owned();
            unlock_page(&st, admin, id.words(), Some(notice), e.status())
        }
        Err(Error::Forbidden) if by_verifier => Err(Error::WrongPassword),
        Err(e) => Err(e),
    }
}
