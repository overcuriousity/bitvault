//! The REST API under `/api/v1`, with no key. Every handler is registered through utoipa-axum, so
//! the spec cannot drift from the routes. The handlers are adapters: the rules are the domain's,
//! and multipart creates and file downloads share the web layer's code.

use std::error::Error as StdError;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http_body_util::LengthLimitError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::domain::paste::{self, Access, Body, DeleteAuth, Paste};
use crate::domain::{self, Privacy, files};
use crate::error::Error;
use crate::ratelimit::{self, RateLimiter};
use crate::security::ClientIp;
use crate::state::AppState;
use crate::web::home::{self, CreateRules, Form, TEXT_LIMIT};
use crate::web::{paste_id, paste_urls};

/// A JSON create body: the text may grow sixfold when escaped (a control character becomes
/// `\u00XX`), plus room for the other fields.
pub const JSON_LIMIT: usize = 6 * TEXT_LIMIT + (64 << 10);
const PASSWORD_HEADER: &str = "x-paste-password";
const VERIFIER_HEADER: &str = "x-paste-verifier";
const UPLOADER_HEADER: &str = "x-uploader-password";
const GRANT_HEADER: &str = "x-paste-grant";
const GRANT_EXPIRED: &str = "The download grant has expired or is no longer valid. Read the paste again for a new one.";

#[derive(OpenApi)]
#[openapi(
    info(
        title = "BitVault API",
        description = "Create, read, edit and delete pastes. There is no API key: every route is open \
and limited per client address. Creating allows 30 requests a minute with a burst of 10; every other \
route allows 120 a minute with a burst of 30. Wrong passwords and verifiers count separately, 10 a \
minute with a burst of 5.

Passwords travel in headers, never in URLs: `X-Paste-Password` opens, edits and deletes read-only and \
private pastes; `X-Paste-Verifier` (64 hex characters, derived in the browser) deletes a secret paste; \
`X-Paste-Grant` carries the `grant` from a paste read to its file downloads; `X-Uploader-Password` is needed to create when the server sets an uploader password.

Errors are JSON `{\"error\": {\"code\": \"...\", \"message\": \"...\"}}`, where `message` is one \
sentence for a person. Codes: `NOT_FOUND` (404; also burned and expired pastes), `PASSWORD_REQUIRED` \
(401), `WRONG_PASSWORD` (403, reading a private paste), `FORBIDDEN` (403; a missing or wrong password \
for an edit or delete, editing switched off, or a missing or wrong uploader password), \
`TOO_MANY_ATTEMPTS` (429), `INVALID` (422, or the status of a malformed request), `TOO_LARGE` (413), \
`UNSUPPORTED_FORMAT` (422), `UNAVAILABLE` (503) and `INTERNAL` (500)."
    ),
    tags((name = "pastes", description = "Pastes and their files.")),
)]
struct Doc;

/// The API's routes, split by route group: creates take large bodies, edits a whole paste's
/// escaped text, the rest the usual limits.
pub struct Routes {
    pub uploads: Router<AppState>,
    pub edits: Router<AppState>,
    pub rest: Router<AppState>,
}

pub fn routes() -> Result<Routes, Error> {
    let (uploads, upload_spec) = OpenApiRouter::new().routes(routes!(create_paste)).split_for_parts();
    let (edits, edit_spec) = OpenApiRouter::new().routes(routes!(update_paste)).split_for_parts();
    let (rest, mut spec) = OpenApiRouter::with_openapi(Doc::openapi())
        .routes(routes!(list_pastes))
        .routes(routes!(get_paste, delete_paste))
        .routes(routes!(get_file))
        .routes(routes!(health))
        .split_for_parts();
    spec.merge(upload_spec);
    spec.merge(edit_spec);
    let json = Bytes::from(spec.to_json().map_err(Error::internal)?);
    let rest = rest.route(
        "/api/v1/openapi.json",
        get(move || {
            let json = json.clone();
            async move { ([(header::CONTENT_TYPE, "application/json")], json) }
        }),
    );
    let api_limiter = Arc::new(RateLimiter::new(120, 30));
    Ok(Routes {
        uploads: uploads.route_layer(ratelimit::layer(Arc::new(RateLimiter::new(30, 10)))),
        // Edits count against the same per-address budget as every other non-create call.
        edits: edits.route_layer(ratelimit::layer(api_limiter.clone())),
        rest: rest.route_layer(ratelimit::layer(api_limiter)),
    })
}

// ---------------------------------------------------------------------------------------------
// Errors

/// An [`Error`] as the API's JSON error body.
#[derive(Debug)]
pub struct ApiError(pub Error);

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}

#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorDetail {
    /// Stable and machine-readable, e.g. `NOT_FOUND`.
    pub code: String,
    /// One sentence for a person.
    pub message: String,
}

fn code(e: &Error) -> &'static str {
    match e {
        Error::NotFound => "NOT_FOUND",
        Error::PasswordRequired => "PASSWORD_REQUIRED",
        Error::WrongPassword => "WRONG_PASSWORD",
        Error::TooManyAttempts => "TOO_MANY_ATTEMPTS",
        Error::Forbidden | Error::UploaderPassword | Error::GrantExpired => "FORBIDDEN",
        Error::Invalid(_) => "INVALID",
        Error::TooLarge => "TOO_LARGE",
        Error::UnsupportedFormat => "UNSUPPORTED_FORMAT",
        Error::IdSpaceExhausted => "UNAVAILABLE",
        Error::Db(_) | Error::Io(_) | Error::Internal(_) => "INTERNAL",
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        self.0.log();
        let message = match self.0 {
            Error::GrantExpired => GRANT_EXPIRED.to_owned(),
            ref e => e.to_string(),
        };
        let body = ErrorBody { error: ErrorDetail { code: code(&self.0).to_owned(), message } };
        (self.0.status(), Json(body)).into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

fn invalid(msg: &str) -> Error {
    Error::Invalid(msg.to_owned())
}

/// The error a plain response under `/api/` stands for, by its status.
fn error_for(status: StatusCode) -> Error {
    match status {
        StatusCode::NOT_FOUND => Error::NotFound,
        StatusCode::UNAUTHORIZED => Error::PasswordRequired,
        StatusCode::FORBIDDEN => Error::Forbidden,
        StatusCode::PAYLOAD_TOO_LARGE => Error::TooLarge,
        StatusCode::TOO_MANY_REQUESTS => Error::TooManyAttempts,
        StatusCode::METHOD_NOT_ALLOWED => invalid("This address does not take that method. See /docs for the API."),
        StatusCode::REQUEST_TIMEOUT => invalid("The request took too long. Try again on a faster connection."),
        s if s.is_server_error() => Error::internal(format!("an API request ended with status {s}")),
        _ => invalid("The request could not be read. Check it against /docs and try again."),
    }
}

/// Responses that did not come from a handler (rate limits, body limits, timeouts, unknown
/// addresses and methods) are plain text; under `/api/` they get the JSON error body, keeping
/// their status.
pub async fn json_errors(req: Request, next: Next) -> Response {
    let api = req.uri().path().starts_with("/api/");
    let res = next.run(req).await;
    let status = res.status();
    let json = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !api || json || !(status.is_client_error() || status.is_server_error()) {
        return res;
    }
    let mut out = ApiError(error_for(status)).into_response();
    *out.status_mut() = status;
    out
}

/// `Json`, with its rejections as API errors.
pub struct ApiJson<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, st: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, st).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(e) => Err(json_rejection(&e).into()),
        }
    }
}

fn json_rejection(e: &JsonRejection) -> Error {
    match e {
        JsonRejection::MissingJsonContentType(_) => invalid("Send the body as application/json."),
        _ if e.status() == StatusCode::PAYLOAD_TOO_LARGE => Error::TooLarge,
        _ => invalid("The JSON body does not match this endpoint. Check it against /docs and try again."),
    }
}

fn body_too_large(e: &axum::Error) -> bool {
    let mut cur: Option<&(dyn StdError + 'static)> = Some(e);
    while let Some(err) = cur {
        if err.is::<LengthLimitError>() {
            return true;
        }
        cur = err.source();
    }
    false
}

/// A header's value as UTF-8 text; an empty value counts as absent.
fn header_text(headers: &HeaderMap, name: &str) -> Result<Option<String>, Error> {
    let Some(value) = headers.get(name) else { return Ok(None) };
    let text = String::from_utf8(value.as_bytes().to_vec())
        .map_err(|_| Error::Invalid(format!("Send the {name} header as UTF-8 text.")))?;
    Ok(Some(text).filter(|t| !t.is_empty()))
}

fn password_access(headers: &HeaderMap) -> Result<Access, Error> {
    Ok(header_text(headers, PASSWORD_HEADER)?.map_or(Access::Anonymous, Access::Password))
}

/// Responses with paste content must not persist in caches.
fn no_store(mut res: Response) -> Response {
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

// ---------------------------------------------------------------------------------------------
// Create

/// A paste to create. Every field but `content` falls back to the server's defaults.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    /// The text, up to 1 MiB. Required unless files are attached (multipart only).
    #[serde(default)]
    pub content: String,
    /// `public`, `unlisted`, `readonly` or `private`, among the levels the server offers. `secret`
    /// is refused: only the browser can encrypt a secret paste.
    #[schema(example = "unlisted")]
    pub privacy: Option<String>,
    /// One of `1min`, `10min`, `1hour`, `24hour`, `3days`, `1week`, `1month`, `6months`, `1year`
    /// or `never`, within the server's choices and maximum.
    #[schema(example = "24hour")]
    pub expiry: Option<String>,
    /// The paste is deleted after this many reads; 0 for no limit.
    pub burn_after_reads: Option<u32>,
    /// A highlighting token such as `rs` or `py`; `plain` or absent for none.
    pub syntax: Option<String>,
    /// Lets readers edit it, when the server allows editing.
    #[serde(default)]
    pub editable: bool,
    /// Required for `readonly` and `private`.
    pub password: Option<String>,
}

/// The multipart form of [`CreateRequest`]: the same fields as parts, plus `file` parts.
// Only describes the body for the spec; `home::read_multipart` reads it.
#[derive(ToSchema)]
#[allow(dead_code)]
struct CreateForm {
    content: Option<String>,
    /// Must come before the first `file` part.
    privacy: Option<String>,
    expiry: Option<String>,
    burn_after_reads: Option<u32>,
    syntax: Option<String>,
    /// `true` or `on`.
    editable: Option<String>,
    password: Option<String>,
    /// Any number of files, each with a file name.
    file: Option<Vec<FileBytes>>,
}

/// A file's bytes.
#[derive(ToSchema)]
#[schema(content_media_type = "application/octet-stream")]
#[allow(dead_code)]
struct FileBytes(String);

impl CreateRequest {
    fn into_form(self) -> Result<Form, Error> {
        if self.content.len() > TEXT_LIMIT {
            return Err(Error::TooLarge);
        }
        Ok(Form {
            content: self.content,
            privacy: self.privacy.as_deref().map(home::parse_privacy).transpose()?,
            expiry: self.expiry.as_deref().map(home::parse_expiry).transpose()?,
            burn_after_reads: self.burn_after_reads,
            syntax: match self.syntax {
                Some(s) => home::parse_syntax(&s)?,
                None => None,
            },
            editable: self.editable,
            password: self.password.filter(|p| !p.is_empty()),
            ..Form::default()
        })
    }
}

#[derive(Serialize, ToSchema)]
pub struct CreateResponse {
    pub id: u64,
    /// The three-word address.
    #[schema(example = "apple-banana-cherry")]
    pub words: String,
    pub url: String,
    /// The address on the short host, when the server has one.
    pub short_url: Option<String>,
    /// Unix seconds; absent for pastes that never expire.
    pub expires_at: Option<i64>,
    pub privacy: String,
}

/// Create a paste.
///
/// Send `application/json`, or `multipart/form-data` to attach files. In a multipart body the
/// order of parts is part of the contract: `privacy` must come before the first `file` part,
/// because files are stored (and encrypted, for private pastes) while they stream in. Secret
/// pastes cannot be created here; they are encrypted in the browser on the home page.
#[utoipa::path(
    post,
    path = "/api/v1/pastes",
    tag = "pastes",
    params(("X-Uploader-Password" = Option<String>, Header, description = "Required when the server sets an uploader password.")),
    request_body(content(
        (CreateRequest = "application/json"),
        (CreateForm = "multipart/form-data"),
    )),
    responses(
        (status = 201, description = "Created.", body = CreateResponse),
        (status = 403, description = "The uploader password is missing or wrong (`FORBIDDEN`).", body = ErrorBody),
        (status = 413, description = "The body is too large (`TOO_LARGE`).", body = ErrorBody),
        (status = 422, description = "A field is invalid, or `privacy` is `secret` (`INVALID`).", body = ErrorBody),
        (status = 429, description = "Too many creates from this address (`TOO_MANY_ATTEMPTS`).", body = ErrorBody),
    )
)]
async fn create_paste(
    State(st): State<AppState>,
    req: Request,
) -> Result<(StatusCode, Json<CreateResponse>), ApiError> {
    home::check_uploader(&st, req.headers().get(UPLOADER_HEADER).map(HeaderValue::as_bytes))?;
    let rules = CreateRules { uploader_checked: true, allow_secret: false };
    // Media types are case-insensitive.
    let content_type =
        req.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_ascii_lowercase();
    let (new, staging) = if content_type.starts_with("multipart/form-data") {
        home::read_multipart(&st, req, rules).await?
    } else if content_type.starts_with("application/json") {
        let bytes = axum::body::to_bytes(req.into_body(), JSON_LIMIT).await.map_err(|e| {
            if body_too_large(&e) { Error::TooLarge } else { invalid("The request body could not be read. Try again.") }
        })?;
        let body: CreateRequest = serde_json::from_slice(&bytes).map_err(|_| {
            invalid("The JSON body does not match this endpoint. Check it against /docs and try again.")
        })?;
        (body.into_form()?.into_new(&st, rules)?, None)
    } else {
        return Err(invalid("Send the paste as application/json or multipart/form-data.").into());
    };
    let now = domain::now();
    let id = paste::create(&st, new, staging, now).await?;
    let p = paste::meta(&st, id, now).await?;
    let words = id.words();
    let (url, short_url) = paste_urls(&st, &words);
    let created = CreateResponse {
        id: id.0,
        words,
        url,
        short_url,
        expires_at: p.expires_at,
        privacy: p.privacy.as_str().to_owned(),
    };
    Ok((StatusCode::CREATED, Json(created)))
}

// ---------------------------------------------------------------------------------------------
// List

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListQuery {
    /// From 1; 50 pastes a page.
    page: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct ListItem {
    pub id: u64,
    pub words: String,
    pub url: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    /// How many files are attached.
    pub files: usize,
}

#[derive(Serialize, ToSchema)]
pub struct ListResponse {
    pub items: Vec<ListItem>,
    pub page: u32,
    /// The next page's number, when this one was full.
    pub next_page: Option<u32>,
}

/// List public pastes, newest first.
///
/// Only addresses and dates: content is read through the paste itself, so reads are counted.
/// Not found when the server has listing switched off.
#[utoipa::path(
    get,
    path = "/api/v1/pastes",
    tag = "pastes",
    params(ListQuery),
    responses(
        (status = 200, description = "One page of public pastes.", body = ListResponse),
        (status = 404, description = "Listing is switched off (`NOT_FOUND`).", body = ErrorBody),
    )
)]
async fn list_pastes(
    State(st): State<AppState>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> ApiResult<ListResponse> {
    if !st.cfg.app.listing {
        return Err(Error::NotFound.into());
    }
    let Query(q) = query.map_err(|_| invalid("Give the page as a whole number from 1."))?;
    let page = q.page.unwrap_or(1).max(1);
    let pastes = paste::list_public(&st, page, domain::now()).await?;
    let full = pastes.len() == paste::PAGE_SIZE as usize;
    let items = pastes
        .iter()
        .map(|p| {
            let words = p.id.words();
            ListItem {
                id: p.id.0,
                url: paste_urls(&st, &words).0,
                words,
                created_at: p.created_at,
                expires_at: p.expires_at,
                files: p.files.len(),
            }
        })
        .collect();
    Ok(Json(ListResponse { items, page, next_page: full.then(|| page.saturating_add(1)) }))
}

// ---------------------------------------------------------------------------------------------
// One paste

#[derive(Serialize, ToSchema)]
pub struct FileItem {
    pub position: u32,
    /// For secret pastes a placeholder; the real name is inside the encrypted content.
    pub name: String,
    /// Stored bytes; for secret pastes, the size of the encrypted container.
    pub size: u64,
    pub mime: String,
    pub url: String,
}

#[derive(Serialize, ToSchema)]
pub struct PasteResponse {
    pub id: u64,
    pub words: String,
    pub url: String,
    pub short_url: Option<String>,
    pub privacy: String,
    /// `text`, or `url` for a paste that is one link.
    pub kind: String,
    pub syntax: Option<String>,
    /// Whether it can be edited now: the server and the paste both allow it.
    pub editable: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub burn_after_reads: u32,
    /// True when this read was the last one allowed; the paste and its files are gone now.
    pub burned: bool,
    /// Reads so far, this one included; only when the server shows read counts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_count: Option<u64>,
    /// True for secret pastes: `content` is then the base64 browser container, which only the
    /// password opens.
    pub encrypted: bool,
    pub content: String,
    pub files: Vec<FileItem>,
    /// A download grant for this paste's files, valid for 600 seconds; send it as `X-Paste-Grant`.
    /// Present after a password read of a private paste (so files need no second key
    /// derivation) and on the burning read (the only way to reach a burned paste's files).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
}

fn paste_response(st: &AppState, p: &Paste, encrypted: bool, content: String, grant: Option<String>) -> PasteResponse {
    let words = p.id.words();
    let (url, short_url) = paste_urls(st, &words);
    let files = p
        .files
        .iter()
        .map(|f| FileItem {
            position: f.position,
            name: f.name.clone(),
            size: f.size,
            mime: f.mime.clone(),
            url: format!("{}/api/v1/pastes/{words}/files/{}", st.dep.origin, f.position),
        })
        .collect();
    PasteResponse {
        id: p.id.0,
        words,
        url,
        short_url,
        privacy: p.privacy.as_str().to_owned(),
        kind: p.kind.as_str().to_owned(),
        syntax: p.syntax.clone(),
        editable: paste::editable(st, p) && p.burned_at.is_none(),
        created_at: p.created_at,
        expires_at: p.expires_at,
        burn_after_reads: p.burn_after_reads,
        burned: p.burned_at.is_some(),
        read_count: st.cfg.app.read_stats.then_some(p.read_count),
        encrypted,
        content,
        files,
        grant,
    }
}

/// Read a paste.
///
/// Counts as a read, so it can burn the paste. A private paste needs `X-Paste-Password`; a
/// secret paste comes back as its encrypted container with `encrypted: true`. The burning read,
/// and a password read of a private paste, return a `grant` for the file downloads.
#[utoipa::path(
    get,
    path = "/api/v1/pastes/{words}",
    tag = "pastes",
    params(
        ("words" = String, Path, description = "The three-word address."),
        ("X-Paste-Password" = Option<String>, Header, description = "Required for private pastes."),
    ),
    responses(
        (status = 200, description = "The paste and its content.", body = PasteResponse),
        (status = 401, description = "A private paste without a password (`PASSWORD_REQUIRED`).", body = ErrorBody),
        (status = 403, description = "The password is wrong (`WRONG_PASSWORD`).", body = ErrorBody),
        (status = 404, description = "No such paste, or burned or expired (`NOT_FOUND`).", body = ErrorBody),
        (status = 429, description = "Too many attempts (`TOO_MANY_ATTEMPTS`).", body = ErrorBody),
    )
)]
async fn get_paste(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    method: Method,
    Path(words): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = paste_id(&words)?;
    // HEAD must not count a read, or it could burn the paste.
    if method == Method::HEAD {
        paste::meta(&st, id, domain::now()).await?;
        return Ok(crate::web::paste::head_only("application/json"));
    }
    let opened = paste::read(&st, id, password_access(&headers)?, ip, domain::now()).await?;
    let (encrypted, content) = match opened.body {
        Body::Text(t) | Body::Url(t) => (false, t),
        Body::Cipher(c) => (true, STANDARD.encode(c)),
    };
    let view = paste_response(&st, &opened.paste, encrypted, content, opened.grant);
    Ok(no_store(Json(view).into_response()))
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EditRequest {
    /// The new text.
    pub content: String,
    /// A highlighting token, or `plain` for none; absent keeps the current one.
    pub syntax: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct EditResponse {
    pub id: u64,
    pub words: String,
    pub url: String,
    pub syntax: Option<String>,
}

/// Edit a paste's content and syntax.
///
/// Needs editing switched on for the server and the paste. Public and unlisted pastes take
/// anyone's edit; read-only and private pastes need `X-Paste-Password`. Secret pastes are never
/// editable.
#[utoipa::path(
    patch,
    path = "/api/v1/pastes/{words}",
    tag = "pastes",
    params(
        ("words" = String, Path, description = "The three-word address."),
        ("X-Paste-Password" = Option<String>, Header, description = "Required for read-only and private pastes."),
    ),
    request_body = EditRequest,
    responses(
        (status = 200, description = "Saved.", body = EditResponse),
        (status = 403, description = "Editing is off, or the password is missing or wrong (`FORBIDDEN`).", body = ErrorBody),
        (status = 404, description = "No such paste (`NOT_FOUND`).", body = ErrorBody),
        (status = 422, description = "The content or syntax is invalid (`INVALID`).", body = ErrorBody),
    )
)]
async fn update_paste(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(words): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<EditRequest>,
) -> ApiResult<EditResponse> {
    let id = paste_id(&words)?;
    let now = domain::now();
    let syntax = match body.syntax {
        Some(s) => home::parse_syntax(&s)?,
        None => paste::meta(&st, id, now).await?.syntax,
    };
    paste::edit(&st, id, password_access(&headers)?, ip, body.content, syntax.clone(), now).await?;
    let words = id.words();
    let url = paste_urls(&st, &words).0;
    Ok(Json(EditResponse { id: id.0, words, url, syntax }))
}

/// Delete a paste and its files, at once and for good.
///
/// Public and unlisted pastes need nothing; read-only and private pastes need
/// `X-Paste-Password`; secret pastes need `X-Paste-Verifier`.
#[utoipa::path(
    delete,
    path = "/api/v1/pastes/{words}",
    tag = "pastes",
    params(
        ("words" = String, Path, description = "The three-word address."),
        ("X-Paste-Password" = Option<String>, Header, description = "For read-only and private pastes."),
        ("X-Paste-Verifier" = Option<String>, Header, description = "For secret pastes: 64 hex characters, HMAC-SHA256 of `bitvault-delete` under the password-derived verifier key."),
    ),
    responses(
        (status = 204, description = "Deleted."),
        (status = 403, description = "The password or verifier is missing or wrong (`FORBIDDEN`).", body = ErrorBody),
        (status = 404, description = "No such paste (`NOT_FOUND`).", body = ErrorBody),
        (status = 422, description = "The verifier is not 64 hex characters (`INVALID`).", body = ErrorBody),
    )
)]
async fn delete_paste(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(words): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let id = paste_id(&words)?;
    let now = domain::now();
    // Each level reads only its own proof, so a stray header for another level changes nothing.
    let auth = match paste::meta(&st, id, now).await?.privacy {
        Privacy::Secret => match header_text(&headers, VERIFIER_HEADER)? {
            Some(v) => {
                let bytes = hex::decode(v.trim()).ok().and_then(|b| <[u8; 32]>::try_from(b).ok());
                DeleteAuth::Verifier(bytes.ok_or_else(|| invalid("Send X-Paste-Verifier as 64 hex characters."))?)
            }
            None => DeleteAuth::None,
        },
        _ => header_text(&headers, PASSWORD_HEADER)?.map_or(DeleteAuth::None, DeleteAuth::Password),
    };
    paste::delete(&st, id, auth, ip, now).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Download one file.
///
/// Does not count as a read. A private paste's files need `X-Paste-Grant` (from reading the
/// paste with its password) or `X-Paste-Password`. A burned paste's files are reachable only with
/// the grant from its burning read, for 600 seconds; an expired paste's files are gone. A secret
/// paste's files come back as their encrypted containers.
#[utoipa::path(
    get,
    path = "/api/v1/pastes/{words}/files/{position}",
    tag = "pastes",
    params(
        ("words" = String, Path, description = "The three-word address."),
        ("position" = u32, Path, description = "The file's position, from 1."),
        ("X-Paste-Grant" = Option<String>, Header, description = "The `grant` from reading the paste; takes precedence over the password."),
        ("X-Paste-Password" = Option<String>, Header, description = "For private pastes, when no grant is sent."),
    ),
    responses(
        (status = 200, description = "The file's bytes.", content_type = "application/octet-stream", body = inline(FileBytes)),
        (status = 401, description = "A private paste without a password (`PASSWORD_REQUIRED`).", body = ErrorBody),
        (status = 403, description = "The password is wrong (`WRONG_PASSWORD`), or the grant is invalid or expired (`FORBIDDEN`).", body = ErrorBody),
        (status = 404, description = "No such paste or file, or burned without a grant (`NOT_FOUND`).", body = ErrorBody),
    )
)]
async fn get_file(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((words, position)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = paste_id(&words)?;
    let position = crate::web::files::position(&position)?;
    let access = match header_text(&headers, GRANT_HEADER)? {
        Some(g) => Access::Grant(g),
        None => password_access(&headers)?,
    };
    let (p, dek) = paste::files_access(&st, id, access, ip, domain::now()).await?;
    let (meta, body) = files::open(&st, id, position, dek.as_ref()).await?;
    Ok(crate::web::files::download(&p, &meta, body)?)
}

// ---------------------------------------------------------------------------------------------
// Health

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    #[schema(example = "ok")]
    pub status: String,
    pub version: String,
}

/// Check that the server answers.
#[utoipa::path(get, path = "/api/v1/health", tag = "pastes", responses((status = 200, body = HealthResponse)))]
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok".to_owned(), version: env!("CARGO_PKG_VERSION").to_owned() })
}
