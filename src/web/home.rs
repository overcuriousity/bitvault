use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use askama::Template;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::header;
use axum::response::{Html, Redirect};
use axum::routing::{get, post};
use futures_util::{StreamExt, TryStreamExt, stream};
use multer::{Field, Multipart};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::multipart::{Guarded, too_large};
use super::page;
use crate::domain::crypto::{self, SALT_LEN};
use crate::domain::expiry::Expiry;
use crate::domain::files::Staging;
use crate::domain::paste::{self, NewPaste, SecretParts};
use crate::domain::{self, Privacy, highlight};
use crate::error::Error;
use crate::ratelimit::{self, RateLimiter};
use crate::state::AppState;

const MIB: u64 = 1 << 20;
/// Each text field of the create form.
const TEXT_LIMIT: usize = 1 << 20;
// A secret paste's content container holds JSON of up to TEXT_LIMIT of text, which escaping can
// grow sixfold (a control character becomes \u00XX), plus 64 KiB of file names and the container
// overhead.
const CONTAINER_LIMIT: usize = crypto::browser_container_max_len(6 * TEXT_LIMIT as u64 + (64 << 10)) as usize;

#[derive(Template)]
#[template(path = "home.html")]
struct Home;

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(index))
}

/// `POST /`, for the upload group: large bodies, a long timeout and the create rate limit.
pub fn upload_routes() -> Router<AppState> {
    Router::new().route("/", post(create).layer(ratelimit::layer(Arc::new(RateLimiter::new(30, 10)))))
}

async fn index(State(st): State<AppState>) -> Result<Html<String>, Error> {
    let body = Home.render().map_err(Error::internal)?;
    page(&st, false, "new", "New paste", body)
}

/// The uploader password, when one is configured, must arrive before any file.
struct Gate<'a> {
    expected: Option<&'a str>,
    passed: bool,
}

impl Gate<'_> {
    fn check(&mut self, given: &[u8]) -> Result<(), Error> {
        let Some(expected) = self.expected else { return Ok(()) };
        // Hashing first makes the comparison independent of both lengths.
        if bool::from(Sha256::digest(given).ct_eq(&Sha256::digest(expected.as_bytes()))) {
            self.passed = true;
            Ok(())
        } else {
            Err(Error::UploaderPassword)
        }
    }

    fn require(&self) -> Result<(), Error> {
        if self.expected.is_none() || self.passed { Ok(()) } else { Err(Error::UploaderPassword) }
    }
}

#[derive(Default)]
struct Form {
    content: String,
    privacy: Option<Privacy>,
    expiry: Option<Expiry>,
    burn_after_reads: Option<u32>,
    syntax: Option<String>,
    editable: bool,
    password: Option<String>,
    content_container: Option<Vec<u8>>,
    verifier_salt: Option<[u8; SALT_LEN]>,
    verifier: Option<[u8; 32]>,
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

fn parse_privacy(value: &str) -> Result<Privacy, Error> {
    Privacy::parse(value.trim()).ok_or_else(|| invalid("Choose a privacy level from the list."))
}

fn default_privacy(st: &AppState) -> Result<Privacy, Error> {
    Privacy::parse(&st.cfg.app.default_privacy).ok_or_else(|| Error::internal("default_privacy is not a privacy level"))
}

fn parse_syntax(value: &str) -> Result<Option<String>, Error> {
    let value = value.trim();
    if value.is_empty() || value == "plain" {
        return Ok(None);
    }
    if highlight::languages().iter().any(|(token, _)| token == value) {
        Ok(Some(value.to_owned()))
    } else {
        Err(invalid("Choose a syntax from the list."))
    }
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
            "expiry" => {
                let v = text(value)?;
                self.expiry = Some(Expiry::parse(v.trim()).ok_or_else(|| invalid("Choose an expiry from the list."))?);
            }
            "burn_after_reads" => {
                let v = text(value)?;
                if !v.trim().is_empty() {
                    self.burn_after_reads = Some(
                        v.trim().parse().map_err(|_| invalid("Enter a whole number of reads, or 0 for no limit."))?,
                    );
                }
            }
            "syntax" => self.syntax = parse_syntax(&text(value)?)?,
            "editable" => self.editable = matches!(text(value)?.trim(), "on" | "true" | "1"),
            "password" => self.password = Some(text(value)?).filter(|p| !p.is_empty()),
            "content_container" => {
                crypto::check_browser_container(&value)?;
                self.content_container = Some(value);
            }
            "verifier_salt" => self.verifier_salt = Some(hex_array(&value)?),
            "verifier" => self.verifier = Some(hex_array(&value)?),
            _ => {}
        }
        Ok(())
    }

    fn into_new(self, st: &AppState) -> Result<NewPaste, Error> {
        let app = &st.cfg.app;
        let privacy = match self.privacy {
            Some(p) => p,
            None => default_privacy(st)?,
        };
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
            editable: self.editable,
            password: self.password,
            secret,
        })
    }
}

/// `POST /`: reads the multipart form in order, streaming each file into a staging directory
/// (encrypted for private pastes) and keeping only the small fields in memory.
async fn create(State(st): State<AppState>, req: Request) -> Result<Redirect, Error> {
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
    let mut gate = Gate { expected: app.uploader_password.as_deref(), passed: false };
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
            }
            continue;
        }
        gate.require()?;
        let privacy = match form.privacy {
            Some(p) => p,
            None => *form.privacy.insert(default_privacy(&st)?),
        };
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
    gate.require()?;
    let new = form.into_new(&st)?;
    let id = paste::create(&st, new, staging, domain::now()).await?;
    Ok(Redirect::to(&format!("/{}", id.words())))
}
