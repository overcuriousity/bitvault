//! The paste page, unlock, raw text, edit and delete.

use askama::Template;
use axum::Form;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use super::admin::MaybeAdmin;
use super::files::{GrantQuery, inline_image};
use super::{
    Extras, IconSize, copy_icons, date, escape_text, icon, page_with, paste_id, paste_urls, privacy_icon,
    privacy_label, render, size,
};
use crate::assets::Assets;
use crate::domain::paste::{self, Access, Body, DeleteAuth, Opened, Paste};
use crate::domain::{self, Kind, Privacy, highlight, qr};
use crate::error::Error;
use crate::security::ClientIp;
use crate::state::AppState;

/// Content above this size is shown plain: syntect's fancy-regex can backtrack badly on large
/// or crafted input, which would make every view of such a paste expensive.
const HIGHLIGHT_LIMIT: usize = 512 * 1024;
const PASSWORD_MISMATCH: &str = "That password does not open this paste. Check it and try again.";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/{words}", get(view))
        .route("/{words}/unlock", post(unlock))
        .route("/{words}/raw", get(raw))
        .route("/{words}/edit", get(edit_form).post(edit))
        .route("/{words}/delete", post(delete))
}

/// How a page's delete form proves the right to delete.
pub struct DeleteView {
    pub action: String,
    /// A password input for read-only and private pastes, unless the admin is signed in.
    pub password: bool,
    /// Hex verifier salt of a secret paste; `secret.js` derives the verifier from it.
    pub salt: String,
}

impl DeleteView {
    fn new(p: &Paste, admin: bool) -> Self {
        let secret = p.privacy == Privacy::Secret && !admin;
        Self {
            action: format!("/{}/delete", p.id.words()),
            password: matches!(p.privacy, Privacy::Readonly | Privacy::Private) && !admin,
            salt: if secret { p.verifier_salt.map(hex::encode).unwrap_or_default() } else { String::new() },
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

#[derive(Template)]
#[template(path = "paste.html")]
struct PasteView {
    word_list: Vec<String>,
    full_url: String,
    short_url: Option<String>,
    privacy_label: &'static str,
    privacy_icon: &'static str,
    facts: Vec<(&'static str, String)>,
    burned: bool,
    secret: bool,
    raw_href: String,
    qr: Option<String>,
    translate: Option<String>,
    edit_href: Option<String>,
    delete: DeleteView,
    /// Escaped or highlighted markup; `None` for a secret paste, which `secret.js` fills.
    content: Option<String>,
    highlighted: bool,
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
    password: bool,
    notice: Option<String>,
}

#[derive(Template)]
#[template(path = "delete.html")]
struct DeletePage {
    words: String,
    notice: String,
    delete: DeleteView,
    trash: String,
}

fn content_html(st: &AppState, text: &str, syntax: Option<&str>) -> (String, bool) {
    if st.cfg.app.highlight
        && text.len() <= HIGHLIGHT_LIMIT
        && let Some(html) = syntax.and_then(|token| highlight::render(text, token))
    {
        return (html, true);
    }
    (escape_text(text), false)
}

fn reads(n: u32) -> String {
    if n == 1 { "1 read".to_owned() } else { format!("{n} reads") }
}

/// The page for a paste whose content (if any) has been read. `grant` is set after an unlock
/// and on the burning read; it is added to the links that need it.
fn paste_view(st: &AppState, admin: bool, p: &Paste, text: Option<&str>, grant: Option<&str>) -> PasteView {
    let app = &st.cfg.app;
    let words = p.id.words();
    let burned = p.burned_at.is_some();
    let secret = p.privacy == Privacy::Secret;
    let files_g = grant.map(|g| format!("?g={g}")).unwrap_or_default();
    // Raw and edit only take a grant from an unlock; a burned paste has neither.
    let read_g = if p.privacy == Privacy::Private { files_g.clone() } else { String::new() };
    let (full, short_url) = paste_urls(st, &words);
    let raw_href = format!("/{words}/raw{read_g}");
    let mut facts = vec![("Created", date(p.created_at))];
    facts.push(("Expires", p.expires_at.map_or_else(|| "Never".to_owned(), date)));
    if p.burn_after_reads > 0 {
        facts.push(("Burns after", reads(p.burn_after_reads)));
    }
    if app.read_stats {
        facts.push(("Reads", p.read_count.to_string()));
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
    let (content, highlighted) = match text {
        Some(t) => {
            let (html, hl) = content_html(st, t, p.syntax.as_deref());
            (Some(html), hl)
        }
        None => (None, false),
    };
    let files = p
        .files
        .iter()
        .map(|f| {
            let href = format!("/{words}/file/{}{files_g}", f.position);
            FileView {
                position: f.position,
                name: f.name.clone(),
                size: if secret { String::new() } else { size(f.size) },
                url: format!("{}{href}", st.dep.origin),
                preview: !secret && inline_image(&f.mime),
                href,
            }
        })
        .collect::<Vec<_>>();
    PasteView {
        word_list: words.split('-').map(str::to_owned).collect(),
        short_url,
        privacy_label: privacy_label(p.privacy),
        privacy_icon: privacy_icon(p.privacy),
        facts,
        burned,
        secret,
        raw_href,
        qr: if app.qr && !burned { qr::svg(&full).ok() } else { None },
        translate,
        edit_href,
        delete: DeleteView::new(p, admin),
        content,
        highlighted,
        zip_href: (!secret && !files.is_empty()).then(|| format!("/{words}/zip{files_g}")),
        files,
        full_url: full,
    }
}

fn render_paste(st: &AppState, admin: bool, view: &PasteView, words: &str) -> Result<Response, Error> {
    let body = render(view)?;
    let js = if view.secret { vec![Assets::url("js/secret.js")] } else { Vec::new() };
    let extras = Extras { css: vec![Assets::url("css/syntax.css")], js, ..Extras::default() };
    Ok(no_store(page_with(st, admin, "", words, body, extras)?.into_response()))
}

/// Pages that carry paste content (decrypted private text, burned pages) must not persist in
/// browser caches or history.
fn no_store(mut res: Response) -> Response {
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn render_opened(st: &AppState, admin: bool, opened: &Opened) -> Result<Response, Error> {
    let text = match &opened.body {
        Body::Text(t) | Body::Url(t) => t.as_str(),
        Body::Cipher(_) => return Err(Error::internal("a secret paste cannot be rendered on the server")),
    };
    let view = paste_view(st, admin, &opened.paste, Some(text), opened.grant.as_deref());
    render_paste(st, admin, &view, &opened.paste.id.words())
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

/// 302 to a URL paste's target; the stored URL was validated as http(s) when it was created.
fn redirect_to(target: &str) -> Result<Response, Error> {
    let location = HeaderValue::from_str(target).or_else(|_| {
        url::Url::parse(target)
            .map_err(Error::internal)
            .and_then(|u| HeaderValue::from_str(u.as_str()).map_err(Error::internal))
    })?;
    Ok((StatusCode::FOUND, [(header::LOCATION, location)]).into_response())
}

/// `GET /{words}`: content for plaintext levels (a read), the unlock form for private (no
/// read), and an empty shell for secret, which the browser fills from `/raw`.
async fn view(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    ClientIp(ip): ClientIp,
    Path(words): Path<String>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let now = domain::now();
    let p = paste::meta(&st, id, now).await?;
    match p.privacy {
        // Only the form: a private paste's file names and sizes are private as well.
        Privacy::Private => unlock_page(&st, admin, id.words(), None, StatusCode::OK),
        Privacy::Secret => {
            let view = paste_view(&st, admin, &p, None, None);
            render_paste(&st, admin, &view, &id.words())
        }
        _ => {
            let opened = paste::read(&st, id, Access::Anonymous, ip, now).await?;
            match &opened.body {
                Body::Url(target) => redirect_to(target),
                _ => render_opened(&st, admin, &opened),
            }
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
    match paste::read(&st, id, Access::Password(form.password), ip, now).await {
        Ok(opened) => render_opened(&st, admin, &opened),
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
            let pw = headers.get("x-paste-password").and_then(|v| v.to_str().ok()).ok_or(Error::PasswordRequired)?;
            Access::Password(pw.to_owned())
        }
        _ => Access::Anonymous,
    };
    let opened = paste::read(&st, id, access, ip, now).await?;
    let (content_type, bytes) = match opened.body {
        Body::Text(t) | Body::Url(t) => ("text/plain; charset=utf-8", t.into_bytes()),
        Body::Cipher(c) => ("application/octet-stream", c),
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

fn syntax_options(st: &AppState, chosen: Option<&str>) -> Vec<(String, String, bool)> {
    let mut options = vec![("plain".to_owned(), "Plain".to_owned(), chosen.is_none())];
    if st.cfg.app.highlight || chosen.is_some() {
        options.extend(highlight::languages().iter().map(|(t, n)| (t.clone(), n.clone(), chosen == Some(t.as_str()))));
    }
    options
}

fn edit_page(
    st: &AppState,
    admin: bool,
    p: &Paste,
    content: String,
    syntax: Option<&str>,
    notice: Option<String>,
    status: StatusCode,
) -> Result<Response, Error> {
    let words = p.id.words();
    let view = EditPage {
        words: words.clone(),
        content,
        syntax_options: syntax_options(st, syntax),
        password: matches!(p.privacy, Privacy::Readonly | Privacy::Private),
        notice,
    };
    let body = render(&view)?;
    let page = page_with(st, admin, "", &format!("Edit {words}"), body, Extras::default())?;
    Ok(no_store((status, page).into_response()))
}

/// `GET /{words}/edit`: the form, prefilled. Showing the content counts as a read; a private
/// paste needs the grant from its unlocked page.
async fn edit_form(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    ClientIp(ip): ClientIp,
    Path(words): Path<String>,
    Query(q): Query<GrantQuery>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let now = domain::now();
    let p = paste::meta(&st, id, now).await?;
    editable(&st, &p)?;
    let access = match (p.privacy, q.g) {
        (Privacy::Private, Some(g)) => Access::Grant(g),
        (Privacy::Private, None) => return Ok(Redirect::to(&format!("/{}", id.words())).into_response()),
        _ => Access::Anonymous,
    };
    let opened = paste::read(&st, id, access, ip, now).await?;
    let content = match opened.body {
        Body::Text(t) | Body::Url(t) => t,
        Body::Cipher(_) => return Err(Error::NotFound),
    };
    edit_page(&st, admin, &opened.paste, content, opened.paste.syntax.as_deref(), None, StatusCode::OK)
}

#[derive(Deserialize)]
struct EditForm {
    #[serde(default)]
    content: String,
    #[serde(default)]
    syntax: String,
    #[serde(default)]
    password: String,
}

/// `POST /{words}/edit`: saves and returns to the paste, or shows the form again with a notice.
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
    let proved = !form.password.is_empty();
    let access = if proved { Access::Password(form.password) } else { Access::Anonymous };
    match paste::edit(&st, id, access, ip, form.content.clone(), syntax.clone(), now).await {
        Ok(()) => Ok(Redirect::to(&format!("/{}", id.words())).into_response()),
        Err(e @ (Error::Forbidden | Error::TooManyAttempts | Error::Invalid(_))) => {
            let message = match &e {
                Error::Forbidden if p.privacy.needs_password() && proved => PASSWORD_MISMATCH.to_owned(),
                Error::Forbidden if p.privacy.needs_password() => "Enter the password to change this paste.".to_owned(),
                other => other.to_string(),
            };
            edit_page(&st, admin, &p, form.content, syntax.as_deref(), Some(message), e.status())
        }
        Err(e) => Err(e),
    }
}

#[derive(Deserialize)]
struct DeleteForm {
    #[serde(default)]
    password: String,
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
/// password; a wrong one shows the delete form again.
async fn delete(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    ClientIp(ip): ClientIp,
    Path(words): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let now = domain::now();
    let proved = !form.password.is_empty() || !form.verifier.is_empty();
    let auth = if admin {
        DeleteAuth::Admin
    } else if !form.verifier.is_empty() {
        DeleteAuth::Verifier(verifier(&form.verifier)?)
    } else if !form.password.is_empty() {
        DeleteAuth::Password(form.password)
    } else {
        DeleteAuth::None
    };
    match paste::delete(&st, id, auth, ip, now).await {
        Ok(()) => {
            let back = if admin && form.next == "admin" { "/admin" } else { "/" };
            Ok(Redirect::to(&format!("{back}?deleted={}", id.words())).into_response())
        }
        Err(e @ (Error::Forbidden | Error::TooManyAttempts)) => {
            let p = paste::meta(&st, id, now).await?;
            let notice = match e {
                Error::Forbidden if proved => PASSWORD_MISMATCH.to_owned(),
                Error::Forbidden => "Enter the password to delete this paste.".to_owned(),
                ref other => other.to_string(),
            };
            let words = id.words();
            let view = DeletePage {
                words: words.clone(),
                notice,
                delete: DeleteView::new(&p, admin),
                trash: icon("trash-2", IconSize::Tool),
            };
            let body = render(&view)?;
            let title = format!("Delete {words}");
            Ok((e.status(), page_with(&st, admin, "", &title, body, Extras::default())?).into_response())
        }
        Err(e) => Err(e),
    }
}
