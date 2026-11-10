//! Text and URL pastes: creation, reads with burn-after-read, edits, deletes and the purge.
//!
//! Every function takes `now` in Unix seconds, so expiry and burning are decided by the caller's
//! clock. A burned or expired row is invisible here: every lookup filters on
//! `burned_at IS NULL AND (expires_at IS NULL OR expires_at > now)`.

use std::fmt;
use std::net::IpAddr;

use linkify::{LinkFinder, LinkKind};

use crate::domain::crypto::{self, Dek, KdfParams, SALT_LEN};
use crate::domain::expiry::{self, Expiry};
use crate::domain::files::{self, FileMeta, PLACEHOLDER_MIME, Staging};
use crate::domain::grant;
use crate::domain::words::PasteId;
use crate::domain::{Kind, Privacy};
use crate::error::Error;
use crate::state::AppState;

/// A burned row stays (invisible) this long, so the burning read's grant can still fetch files.
pub const BURNED_TTL_SECS: i64 = 600;
pub const PAGE_SIZE: u32 = 50;
/// The most text a paste may hold, in bytes.
pub const TEXT_LIMIT: usize = 1 << 20;
const INSERT_ATTEMPTS: usize = 8;

/// What a creator submits. `content` is ignored for secret pastes, whose text is inside `secret`.
pub struct NewPaste {
    pub content: String,
    pub privacy: Privacy,
    pub expiry: Expiry,
    pub burn_after_reads: u32,
    pub syntax: Option<String>,
    pub editable: bool,
    pub password: Option<String>,
    pub secret: Option<SecretParts>,
}

/// What the browser sends for a secret paste; the password itself never reaches the server.
pub struct SecretParts {
    pub container: Vec<u8>,
    pub verifier_salt: [u8; SALT_LEN],
    pub verifier: [u8; 32],
}

/// How a reader or editor proves access. The admin gets no extra read or edit rights.
pub enum Access {
    Anonymous,
    Password(String),
    Grant(String),
    Admin,
}

impl fmt::Debug for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Anonymous => "Anonymous",
            Self::Password(_) => "Password(..)",
            Self::Grant(_) => "Grant(..)",
            Self::Admin => "Admin",
        })
    }
}

/// How a deleter proves the right to delete.
pub enum DeleteAuth {
    None,
    Password(String),
    Verifier([u8; 32]),
    Admin,
}

impl fmt::Debug for DeleteAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Password(_) => "Password(..)",
            Self::Verifier(_) => "Verifier(..)",
            Self::Admin => "Admin",
        })
    }
}

/// A stored paste's metadata, as in the `pastes` table. The content itself is loaded only by a
/// counted read ([`read`]), which hands it back in [`Opened::body`].
#[derive(Clone)]
pub struct Paste {
    pub id: PasteId,
    pub kind: Kind,
    pub privacy: Privacy,
    /// Stored bytes of the content: UTF-8 text, or a crypto container for private and secret pastes.
    pub content_len: u64,
    pub syntax: Option<String>,
    pub editable: bool,
    pub password_hash: Option<String>,
    pub wrapped_key: Option<Vec<u8>>,
    /// `verifier_salt ‖ SHA-256(verifier)`.
    pub verifier_hash: Option<Vec<u8>>,
    pub verifier_salt: Option<[u8; SALT_LEN]>,
    pub burn_after_reads: u32,
    pub read_count: u64,
    pub last_read_at: Option<i64>,
    pub burned_at: Option<i64>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    /// Attachments in position order.
    pub files: Vec<FileMeta>,
}

impl fmt::Debug for Paste {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |present: bool| if present { "***" } else { "-" };
        f.debug_struct("Paste")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("privacy", &self.privacy)
            .field("content_len", &self.content_len)
            .field("syntax", &self.syntax)
            .field("editable", &self.editable)
            .field("password_hash", &redact(self.password_hash.is_some()))
            .field("wrapped_key", &redact(self.wrapped_key.is_some()))
            .field("verifier_hash", &redact(self.verifier_hash.is_some()))
            .field("burn_after_reads", &self.burn_after_reads)
            .field("read_count", &self.read_count)
            .field("last_read_at", &self.last_read_at)
            .field("burned_at", &self.burned_at)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("files", &self.files.len())
            .finish()
    }
}

/// What a read hands back.
pub enum Body {
    Text(String),
    /// The target of a URL paste.
    Url(String),
    /// A secret paste's browser container, decrypted only in the browser.
    Cipher(Vec<u8>),
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(t) => write!(f, "Text({} bytes)", t.len()),
            Self::Url(u) => write!(f, "Url({} bytes)", u.len()),
            Self::Cipher(c) => write!(f, "Cipher({} bytes)", c.len()),
        }
    }
}

/// A counted read. `grant` is set after a private unlock and on the burning read.
pub struct Opened {
    pub paste: Paste,
    pub body: Body,
    pub grant: Option<String>,
}

impl fmt::Debug for Opened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opened")
            .field("paste", &self.paste)
            .field("body", &self.body)
            .field("grant", &self.grant.as_ref().map(|_| "***"))
            .finish()
    }
}

/// Row shape shared by every metadata query; `content_len` is `length(content)`, so the content
/// is never loaded.
struct Row {
    id: i64,
    kind: String,
    privacy: String,
    content_len: i64,
    syntax: Option<String>,
    editable: bool,
    password_hash: Option<String>,
    wrapped_key: Option<Vec<u8>>,
    verifier_hash: Option<Vec<u8>>,
    burn_after_reads: i64,
    read_count: i64,
    last_read_at: Option<i64>,
    burned_at: Option<i64>,
    created_at: i64,
    expires_at: Option<i64>,
}

impl TryFrom<Row> for Paste {
    type Error = Error;

    fn try_from(r: Row) -> Result<Self, Error> {
        let corrupt = |what: &str| Error::internal(format!("paste {} has an invalid {what}", r.id));
        let verifier_salt = match r.verifier_hash.as_deref() {
            Some(v) => Some(v.first_chunk::<SALT_LEN>().copied().ok_or_else(|| corrupt("verifier"))?),
            None => None,
        };
        Ok(Self {
            id: PasteId(u64::try_from(r.id).map_err(|_| corrupt("id"))?),
            kind: Kind::parse(&r.kind).ok_or_else(|| corrupt("kind"))?,
            privacy: Privacy::parse(&r.privacy).ok_or_else(|| corrupt("privacy"))?,
            burn_after_reads: u32::try_from(r.burn_after_reads).map_err(|_| corrupt("burn count"))?,
            read_count: u64::try_from(r.read_count).map_err(|_| corrupt("read count"))?,
            content_len: u64::try_from(r.content_len).map_err(|_| corrupt("content length"))?,
            verifier_salt,
            syntax: r.syntax,
            editable: r.editable,
            password_hash: r.password_hash,
            wrapped_key: r.wrapped_key,
            verifier_hash: r.verifier_hash,
            last_read_at: r.last_read_at,
            burned_at: r.burned_at,
            created_at: r.created_at,
            expires_at: r.expires_at,
            files: Vec::new(),
        })
    }
}

/// [`Row`] plus the content, for the counted read.
struct ReadRow {
    id: i64,
    kind: String,
    privacy: String,
    content: Vec<u8>,
    syntax: Option<String>,
    editable: bool,
    password_hash: Option<String>,
    wrapped_key: Option<Vec<u8>>,
    verifier_hash: Option<Vec<u8>>,
    burn_after_reads: i64,
    read_count: i64,
    last_read_at: Option<i64>,
    burned_at: Option<i64>,
    created_at: i64,
    expires_at: Option<i64>,
}

impl ReadRow {
    fn split(self) -> Result<(Paste, Vec<u8>), Error> {
        let row = Row {
            id: self.id,
            kind: self.kind,
            privacy: self.privacy,
            content_len: i64::try_from(self.content.len()).map_err(Error::internal)?,
            syntax: self.syntax,
            editable: self.editable,
            password_hash: self.password_hash,
            wrapped_key: self.wrapped_key,
            verifier_hash: self.verifier_hash,
            burn_after_reads: self.burn_after_reads,
            read_count: self.read_count,
            last_read_at: self.last_read_at,
            burned_at: self.burned_at,
            created_at: self.created_at,
            expires_at: self.expires_at,
        };
        Ok((row.try_into()?, self.content))
    }
}

fn db_id(id: PasteId) -> i64 {
    // IDs are below 2^33, so this never saturates.
    i64::try_from(id.0).unwrap_or(i64::MAX)
}

#[cfg(feature = "test-hooks")]
thread_local! {
    static ID_SOURCE: std::cell::RefCell<std::collections::VecDeque<u64>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

/// Makes the next creates on this thread try these IDs, in order, before random ones. Test-only.
#[cfg(feature = "test-hooks")]
pub fn set_id_source(ids: Vec<u64>) {
    ID_SOURCE.with_borrow_mut(|q| *q = ids.into());
}

fn next_id() -> PasteId {
    #[cfg(feature = "test-hooks")]
    if let Some(id) = ID_SOURCE.with_borrow_mut(|q| q.pop_front()) {
        return PasteId(id & ((1 << crate::domain::words::ID_BITS) - 1));
    }
    PasteId::random()
}

/// The URL when the whole trimmed content is exactly one http(s) link.
fn whole_url(content: &str) -> Option<&str> {
    let trimmed = content.trim();
    let mut finder = LinkFinder::new();
    finder.kinds(&[LinkKind::Url]);
    let mut links = finder.links(trimmed);
    let link = links.next()?;
    let whole = links.next().is_none() && link.start() == 0 && link.end() == trimmed.len();
    // Only web links become redirects; other schemes stay text.
    let web = url::Url::parse(trimmed).is_ok_and(|u| matches!(u.scheme(), "http" | "https"));
    (whole && web).then_some(trimmed)
}

/// Kind and stored bytes for plaintext content at `privacy`. A paste with files stays text, so
/// its files are never hidden behind a redirect.
fn plain_content(privacy: Privacy, content: String, has_files: bool) -> (Kind, Vec<u8>) {
    if matches!(privacy, Privacy::Public | Privacy::Unlisted)
        && !has_files
        && let Some(url) = whole_url(&content)
    {
        return (Kind::Url, url.as_bytes().to_vec());
    }
    (Kind::Text, content.into_bytes())
}

/// Text is optional only when the paste carries files.
fn require_content(content: &str, has_files: bool) -> Result<(), Error> {
    if content.trim().is_empty() && !has_files {
        return Err(Error::Invalid("Enter some text to paste.".into()));
    }
    Ok(())
}

fn require_password(privacy: Privacy, password: Option<&str>) -> Result<&str, Error> {
    match password {
        Some(pw) if !pw.is_empty() => Ok(pw),
        _ => {
            let level = if privacy == Privacy::Readonly { "read-only" } else { "private" };
            Err(Error::Invalid(format!("Enter a password for a {level} paste.")))
        }
    }
}

struct Stored {
    kind: Kind,
    content: Vec<u8>,
    password_hash: Option<String>,
    wrapped_key: Option<Vec<u8>>,
    verifier_hash: Option<Vec<u8>>,
}

/// `dek` is the staging's data key when files were encrypted for this paste.
async fn prepare(new: NewPaste, has_files: bool, dek: Option<&Dek>) -> Result<Stored, Error> {
    let none = |kind, content| Stored { kind, content, password_hash: None, wrapped_key: None, verifier_hash: None };
    match new.privacy {
        Privacy::Public | Privacy::Unlisted => {
            require_content(&new.content, has_files)?;
            let (kind, content) = plain_content(new.privacy, new.content, has_files);
            Ok(none(kind, content))
        }
        Privacy::Readonly => {
            require_content(&new.content, has_files)?;
            let pw = require_password(new.privacy, new.password.as_deref())?;
            let hash = crypto::hash_password(pw).await?;
            Ok(Stored { password_hash: Some(hash), ..none(Kind::Text, new.content.into_bytes()) })
        }
        Privacy::Private => {
            require_content(&new.content, has_files)?;
            let pw = require_password(new.privacy, new.password.as_deref())?;
            let fresh;
            let dek = match dek {
                Some(dek) => dek,
                None => {
                    fresh = Dek::random();
                    &fresh
                }
            };
            let sealed = crypto::seal(dek, new.content.as_bytes());
            let wrapped = crypto::wrap_dek(pw, dek, KdfParams::DEFAULT).await?;
            Ok(Stored { wrapped_key: Some(wrapped), ..none(Kind::Text, sealed) })
        }
        Privacy::Secret => {
            let Some(parts) = new.secret else {
                return Err(Error::Invalid(
                    "A secret paste must be encrypted in the browser. Enable JavaScript.".into(),
                ));
            };
            crypto::check_browser_container(&parts.container)?;
            let mut verifier = parts.verifier_salt.to_vec();
            verifier.extend_from_slice(&crypto::verifier_hash(&parts.verifier));
            Ok(Stored { verifier_hash: Some(verifier), ..none(Kind::Text, parts.container) })
        }
    }
}

/// The staged files must have been written the way this paste's level stores them.
fn check_staging(privacy: Privacy, staging: &Staging) -> Result<(), Error> {
    if staging.files().is_empty() {
        return Ok(());
    }
    if staging.dek().is_some() != (privacy == Privacy::Private) {
        return Err(Error::internal("the staged files are not encrypted the way this privacy level needs"));
    }
    let placeholders =
        staging.files().iter().all(|f| f.name == format!("file-{}", f.position) && f.mime == PLACEHOLDER_MIME);
    if privacy == Privacy::Secret && !placeholders {
        return Err(Error::internal("a secret paste's files must carry placeholder names"));
    }
    Ok(())
}

/// Stores a new paste under a fresh random ID, retrying on collisions. Staged files are moved
/// into `files/<id>/` in the same transaction that inserts the row and its `paste_files`, so a
/// failure anywhere leaves neither the row nor the files.
pub async fn create(st: &AppState, new: NewPaste, staging: Option<Staging>, now: i64) -> Result<PasteId, Error> {
    let cfg = &st.cfg.app;
    if !cfg.privacy_levels.iter().any(|l| l == new.privacy.as_str()) {
        return Err(Error::Invalid("That privacy level is not offered here. Choose another one.".into()));
    }
    if !expiry::allowed(cfg, new.expiry) {
        let msg = if !expiry::within_max(cfg, new.expiry) {
            format!("Choose an expiry of {} or less.", expiry::max(cfg).label())
        } else {
            "That expiry is not offered here. Choose one from the list.".to_owned()
        };
        return Err(Error::Invalid(msg));
    }
    let privacy = new.privacy;
    let syntax = new.syntax.clone();
    let editable = new.editable && privacy != Privacy::Secret;
    let burn = i64::from(new.burn_after_reads);
    let expires_at = new.expiry.seconds().map(|s| now.saturating_add(s));
    let mut staging = staging.filter(|s| !s.files().is_empty());
    if let Some(staging) = &staging {
        check_staging(privacy, staging)?;
    }
    let s = prepare(new, staging.is_some(), staging.as_ref().and_then(Staging::dek)).await?;
    let (kind, privacy) = (s.kind.as_str(), privacy.as_str());
    for _ in 0..INSERT_ATTEMPTS {
        let id = next_id();
        let db = db_id(id);
        let mut tx = st.pool.begin().await?;
        let inserted = sqlx::query!(
            "INSERT INTO pastes (id, kind, privacy, content, syntax, editable, password_hash, wrapped_key,
                                 verifier_hash, burn_after_reads, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (id) DO NOTHING",
            db,
            kind,
            privacy,
            s.content,
            syntax,
            editable,
            s.password_hash,
            s.wrapped_key,
            s.verifier_hash,
            burn,
            now,
            expires_at,
        )
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            continue;
        }
        let Some(staging) = staging.as_mut() else {
            tx.commit().await?;
            return Ok(id);
        };
        for f in staging.files() {
            let (position, size) = (i64::from(f.position), i64::try_from(f.size).map_err(|_| Error::TooLarge)?);
            sqlx::query!(
                "INSERT INTO paste_files (paste_id, position, name, size, mime) VALUES (?, ?, ?, ?, ?)",
                db,
                position,
                f.name,
                size,
                f.mime,
            )
            .execute(&mut *tx)
            .await?;
        }
        // Dropping the transaction on any error below rolls the row back; dropping the staging
        // removes the files it still holds.
        let target = files::dir(st, id);
        staging.commit(&target).await?;
        if let Err(e) = tx.commit().await {
            if let Err(rm) = tokio::fs::remove_dir_all(&target).await {
                tracing::warn!(error = %rm, "could not remove the files of a paste that failed to commit");
            }
            return Err(e.into());
        }
        return Ok(id);
    }
    Err(Error::IdSpaceExhausted)
}

/// The paste without counting a read.
pub async fn meta(st: &AppState, id: PasteId, now: i64) -> Result<Paste, Error> {
    let db = db_id(id);
    let row = sqlx::query_as!(
        Row,
        r#"SELECT id AS "id!", kind AS "kind!", privacy AS "privacy!", length(content) AS "content_len!: i64",
                  syntax AS "syntax?", editable AS "editable!: bool", password_hash AS "password_hash?", wrapped_key AS "wrapped_key?",
                  verifier_hash AS "verifier_hash?", burn_after_reads AS "burn_after_reads!",
                  read_count AS "read_count!", last_read_at AS "last_read_at?", burned_at AS "burned_at?",
                  created_at AS "created_at!", expires_at AS "expires_at?"
           FROM pastes
           WHERE id = ? AND burned_at IS NULL AND (expires_at IS NULL OR expires_at > ?)"#,
        db,
        now,
    )
    .fetch_optional(&st.pool)
    .await?
    .ok_or(Error::NotFound)?;
    with_files(st, row.try_into()?).await
}

/// The paste and its content without counting a read, for the creator's page right after a
/// create. Private and secret pastes give no content: their text is sealed under a password the
/// server does not hold here.
pub async fn creator_view(st: &AppState, id: PasteId, now: i64) -> Result<(Paste, Option<Body>), Error> {
    let db = db_id(id);
    let row = sqlx::query_as!(
        ReadRow,
        r#"SELECT id AS "id!", kind AS "kind!", privacy AS "privacy!", content AS "content!",
                  syntax AS "syntax?", editable AS "editable!: bool", password_hash AS "password_hash?",
                  wrapped_key AS "wrapped_key?", verifier_hash AS "verifier_hash?",
                  burn_after_reads AS "burn_after_reads!", read_count AS "read_count!",
                  last_read_at AS "last_read_at?", burned_at AS "burned_at?", created_at AS "created_at!",
                  expires_at AS "expires_at?"
           FROM pastes
           WHERE id = ? AND burned_at IS NULL AND (expires_at IS NULL OR expires_at > ?)"#,
        db,
        now,
    )
    .fetch_optional(&st.pool)
    .await?
    .ok_or(Error::NotFound)?;
    let (paste, content) = row.split()?;
    let body = match (paste.privacy, paste.kind) {
        (Privacy::Private | Privacy::Secret, _) => None,
        (_, Kind::Url) => Some(Body::Url(utf8(content)?)),
        (_, Kind::Text) => Some(Body::Text(utf8(content)?)),
    };
    Ok((with_files(st, paste).await?, body))
}

/// Like [`meta`], but also finds a paste that burned less than [`BURNED_TTL_SECS`] ago, so the
/// burning read's grant can still fetch its files. Only for callers holding a valid grant for `id`.
pub async fn meta_for_grant(st: &AppState, id: PasteId, now: i64) -> Result<Paste, Error> {
    let db = db_id(id);
    let burned_after = now.saturating_sub(BURNED_TTL_SECS);
    let row = sqlx::query_as!(
        Row,
        r#"SELECT id AS "id!", kind AS "kind!", privacy AS "privacy!", length(content) AS "content_len!: i64",
                  syntax AS "syntax?", editable AS "editable!: bool", password_hash AS "password_hash?", wrapped_key AS "wrapped_key?",
                  verifier_hash AS "verifier_hash?", burn_after_reads AS "burn_after_reads!",
                  read_count AS "read_count!", last_read_at AS "last_read_at?", burned_at AS "burned_at?",
                  created_at AS "created_at!", expires_at AS "expires_at?"
           FROM pastes
           WHERE id = ? AND (burned_at IS NULL OR burned_at > ?) AND (expires_at IS NULL OR expires_at > ?)"#,
        db,
        burned_after,
        now,
    )
    .fetch_optional(&st.pool)
    .await?
    .ok_or(Error::NotFound)?;
    with_files(st, row.try_into()?).await
}

async fn with_files(st: &AppState, mut p: Paste) -> Result<Paste, Error> {
    p.files = files::list(st, p.id).await?;
    Ok(p)
}

/// The pastes of `rows` with their files, which one query loads for all of them.
async fn with_files_of_all(st: &AppState, rows: Vec<Row>) -> Result<Vec<Paste>, Error> {
    let mut pastes = rows.into_iter().map(Paste::try_from).collect::<Result<Vec<_>, _>>()?;
    let mut files = files::list_for(st, &pastes.iter().map(|p| p.id).collect::<Vec<_>>()).await?;
    for p in &mut pastes {
        p.files = files.remove(&p.id).unwrap_or_default();
    }
    Ok(pastes)
}

/// Counts one read in a single statement, burning the row on its last allowed read, and returns
/// the paste with its content. `None` means the row is gone, burned or expired.
async fn count_read(st: &AppState, id: PasteId, now: i64) -> Result<Option<(Paste, Vec<u8>)>, Error> {
    let db = db_id(id);
    let row = sqlx::query_as!(
        ReadRow,
        r#"UPDATE pastes SET read_count = read_count + 1, last_read_at = ?,
                  burned_at = CASE WHEN burn_after_reads > 0 AND read_count + 1 >= burn_after_reads THEN ? END
           WHERE id = ? AND burned_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
           RETURNING id AS "id!", kind AS "kind!", privacy AS "privacy!", content AS "content!",
                     syntax AS "syntax?", editable AS "editable!: bool", password_hash AS "password_hash?",
                     wrapped_key AS "wrapped_key?", verifier_hash AS "verifier_hash?",
                     burn_after_reads AS "burn_after_reads!", read_count AS "read_count!",
                     last_read_at AS "last_read_at?", burned_at AS "burned_at?", created_at AS "created_at!",
                     expires_at AS "expires_at?""#,
        now,
        now,
        db,
        now,
    )
    .fetch_optional(&st.pool)
    .await?;
    match row {
        Some(row) => {
            let (paste, content) = row.split()?;
            Ok(Some((with_files(st, paste).await?, content)))
        }
        None => Ok(None),
    }
}

/// Runs a password or verifier check under the failed-attempt limiter. A token is taken before
/// the (slow) check, so parallel guesses cannot outrun the limit, and given back unless the
/// proof was wrong, so right passwords cost nothing.
async fn limited<T>(st: &AppState, ip: IpAddr, check: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
    st.failures.take(ip)?;
    let out = check.await;
    if !matches!(out, Err(Error::WrongPassword | Error::Forbidden)) {
        st.failures.refund(ip);
    }
    out
}

/// Recovers a private paste's data key; a wrong password counts as a failed attempt.
async fn unlock(st: &AppState, p: &Paste, password: &str, ip: IpAddr) -> Result<Dek, Error> {
    let wrapped = p.wrapped_key.as_deref().ok_or_else(|| Error::internal("a private paste has no wrapped key"))?;
    limited(st, ip, crypto::unwrap_dek(password, wrapped)).await
}

/// Checks a read-only paste's password; a wrong one counts as a failed attempt.
async fn check_readonly(st: &AppState, p: &Paste, password: &str, ip: IpAddr) -> Result<(), Error> {
    let phc = p.password_hash.as_deref().ok_or_else(|| Error::internal("a read-only paste has no password hash"))?;
    limited(st, ip, async { if crypto::verify_password(password, phc).await { Ok(()) } else { Err(Error::Forbidden) } })
        .await
}

/// Checks a secret paste's delete verifier; a wrong one counts as a failed attempt.
async fn check_verifier(st: &AppState, p: &Paste, given: &[u8; 32], ip: IpAddr) -> Result<(), Error> {
    let stored = p.verifier_hash.as_deref().and_then(|h| h.get(SALT_LEN..)).unwrap_or_default();
    limited(st, ip, async { if crypto::verifier_matches(stored, given) { Ok(()) } else { Err(Error::Forbidden) } })
        .await
}

fn utf8(bytes: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(bytes).map_err(Error::internal)
}

/// Opens a paste for reading and counts the read. Private pastes need the password or a grant;
/// a secret paste returns its ciphertext.
pub async fn read(st: &AppState, id: PasteId, access: Access, ip: IpAddr, now: i64) -> Result<Opened, Error> {
    let found = meta(st, id, now).await?;
    let mut fresh_grant = false;
    let dek = match (found.privacy, access) {
        (Privacy::Private, Access::Password(pw)) => {
            fresh_grant = true;
            Some(unlock(st, &found, &pw, ip).await?)
        }
        (Privacy::Private, Access::Grant(token)) => {
            Some(grant::check(&st.grant_key, &token, id, now)?.ok_or(Error::GrantExpired)?)
        }
        (Privacy::Private, Access::Anonymous | Access::Admin) => return Err(Error::PasswordRequired),
        _ => None,
    };
    let (paste, content) = count_read(st, id, now).await?.ok_or(Error::NotFound)?;
    let burning = paste.burned_at.is_some();
    let body = match (&dek, paste.kind) {
        (Some(dek), _) => Body::Text(utf8(crypto::open(dek, &content)?)?),
        (None, _) if paste.privacy == Privacy::Secret => Body::Cipher(content),
        (None, Kind::Url) => Body::Url(utf8(content)?),
        (None, Kind::Text) => Body::Text(utf8(content)?),
    };
    let grant = (fresh_grant || burning).then(|| grant::issue(&st.grant_key, id, dek.as_ref(), now));
    Ok(Opened { paste, body, grant })
}

/// The paste whose files may be served, and the data key to decrypt them with. Downloads do not
/// count as reads, and `files::open` and `files::zip` apply no rules, so every caller goes
/// through here first.
///
/// - A live paste of a plaintext level, or a secret paste (served as ciphertext): no proof needed.
/// - A private paste: the password (a wrong one counts as a failed attempt) or a grant carrying
///   its data key; with neither, [`Error::PasswordRequired`].
/// - A burned paste: only with a valid grant, within its ten minutes; otherwise not found.
pub async fn files_access(
    st: &AppState,
    id: PasteId,
    access: Access,
    ip: IpAddr,
    now: i64,
) -> Result<(Paste, Option<Dek>), Error> {
    if let Access::Grant(token) = access {
        let dek = grant::check(&st.grant_key, &token, id, now)?;
        let p = meta_for_grant(st, id, now).await?;
        if p.privacy == Privacy::Private && dek.is_none() {
            return Err(Error::GrantExpired);
        }
        return Ok((p, dek));
    }
    let p = meta(st, id, now).await?;
    match (p.privacy, access) {
        (Privacy::Private, Access::Password(pw)) => {
            let dek = unlock(st, &p, &pw, ip).await?;
            Ok((p, Some(dek)))
        }
        (Privacy::Private, _) => Err(Error::PasswordRequired),
        _ => Ok((p, None)),
    }
}

/// Editing needs the config switch and the paste's own flag, and is never allowed for secret.
pub fn editable(st: &AppState, p: &Paste) -> bool {
    st.cfg.app.editable && p.editable && p.privacy != Privacy::Secret
}

/// Replaces the content and syntax of an editable paste. Secret pastes are never editable.
pub async fn edit(
    st: &AppState,
    id: PasteId,
    access: Access,
    ip: IpAddr,
    content: String,
    syntax: Option<String>,
    now: i64,
) -> Result<(), Error> {
    let p = meta(st, id, now).await?;
    if !editable(st, &p) {
        return Err(Error::Forbidden);
    }
    if content.len() > TEXT_LIMIT {
        return Err(Error::TooLarge);
    }
    let has_files = !p.files.is_empty();
    require_content(&content, has_files)?;
    let (kind, stored) = match (p.privacy, access) {
        (Privacy::Public | Privacy::Unlisted, _) => plain_content(p.privacy, content, has_files),
        (Privacy::Readonly, Access::Password(pw)) => {
            check_readonly(st, &p, &pw, ip).await?;
            (Kind::Text, content.into_bytes())
        }
        (Privacy::Private, Access::Password(pw)) => {
            let dek = match unlock(st, &p, &pw, ip).await {
                Err(Error::WrongPassword) => return Err(Error::Forbidden),
                other => other?,
            };
            (Kind::Text, crypto::seal(&dek, content.as_bytes()))
        }
        _ => return Err(Error::Forbidden),
    };
    let (db, kind) = (db_id(id), kind.as_str());
    let updated = sqlx::query!(
        "UPDATE pastes SET content = ?, syntax = ?, kind = ?
         WHERE id = ? AND burned_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
        stored,
        syntax,
        kind,
        db,
        now,
    )
    .execute(&st.pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

async fn remove_files(st: &AppState, id: PasteId) -> Result<(), Error> {
    match tokio::fs::remove_dir_all(files::dir(st, id)).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// Deletes a paste and its files at once, under the §4 rules; the admin may delete any paste.
pub async fn delete(st: &AppState, id: PasteId, auth: DeleteAuth, ip: IpAddr, now: i64) -> Result<(), Error> {
    let p = meta(st, id, now).await?;
    match (p.privacy, auth) {
        (_, DeleteAuth::Admin) | (Privacy::Public | Privacy::Unlisted, _) => {}
        (Privacy::Readonly, DeleteAuth::Password(pw)) => check_readonly(st, &p, &pw, ip).await?,
        (Privacy::Private, DeleteAuth::Password(pw)) => match unlock(st, &p, &pw, ip).await {
            Err(Error::WrongPassword) => return Err(Error::Forbidden),
            other => other.map(|_| ())?,
        },
        (Privacy::Secret, DeleteAuth::Verifier(v)) => check_verifier(st, &p, &v, ip).await?,
        _ => return Err(Error::Forbidden),
    }
    let db = db_id(id);
    // The same liveness guard as every other statement: a paste that burned or expired since
    // `meta` keeps its files for the burning read's grant until the purge.
    let deleted = sqlx::query!(
        "DELETE FROM pastes WHERE id = ? AND burned_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
        db,
        now,
    )
    .execute(&st.pool)
    .await?;
    if deleted.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    // The paste is gone either way; a leftover directory is removed by the start-up orphan sweep.
    if let Err(e) = remove_files(st, id).await {
        tracing::warn!(error = %e, "could not remove a deleted paste's files");
    }
    Ok(())
}

/// Live public pastes, newest first, [`PAGE_SIZE`] per page; pages count from 1 (0 is page 1).
pub async fn list_public(st: &AppState, page: u32, now: i64) -> Result<Vec<Paste>, Error> {
    let offset = i64::from(page.saturating_sub(1)) * i64::from(PAGE_SIZE);
    let limit = i64::from(PAGE_SIZE);
    let rows = sqlx::query_as!(
        Row,
        r#"SELECT id AS "id!", kind AS "kind!", privacy AS "privacy!", length(content) AS "content_len!: i64",
                  syntax AS "syntax?", editable AS "editable!: bool", password_hash AS "password_hash?", wrapped_key AS "wrapped_key?",
                  verifier_hash AS "verifier_hash?", burn_after_reads AS "burn_after_reads!",
                  read_count AS "read_count!", last_read_at AS "last_read_at?", burned_at AS "burned_at?",
                  created_at AS "created_at!", expires_at AS "expires_at?"
           FROM pastes
           WHERE privacy = 'public' AND burned_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
           ORDER BY created_at DESC, id DESC
           LIMIT ? OFFSET ?"#,
        now,
        limit,
        offset,
    )
    .fetch_all(&st.pool)
    .await?;
    with_files_of_all(st, rows).await
}

/// Live pastes of every level, newest first, [`PAGE_SIZE`] per page like [`list_public`], for
/// the admin table.
pub async fn list_all(st: &AppState, page: u32, now: i64) -> Result<Vec<Paste>, Error> {
    let offset = i64::from(page.saturating_sub(1)) * i64::from(PAGE_SIZE);
    let limit = i64::from(PAGE_SIZE);
    let rows = sqlx::query_as!(
        Row,
        r#"SELECT id AS "id!", kind AS "kind!", privacy AS "privacy!", length(content) AS "content_len!: i64",
                  syntax AS "syntax?", editable AS "editable!: bool", password_hash AS "password_hash?", wrapped_key AS "wrapped_key?",
                  verifier_hash AS "verifier_hash?", burn_after_reads AS "burn_after_reads!",
                  read_count AS "read_count!", last_read_at AS "last_read_at?", burned_at AS "burned_at?",
                  created_at AS "created_at!", expires_at AS "expires_at?"
           FROM pastes
           WHERE burned_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
           ORDER BY created_at DESC, id DESC
           LIMIT ? OFFSET ?"#,
        now,
        limit,
        offset,
    )
    .fetch_all(&st.pool)
    .await?;
    with_files_of_all(st, rows).await
}

/// How much the live pastes hold together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Totals {
    pub pastes: u64,
    /// Stored bytes of text and links.
    pub content_bytes: u64,
    pub file_bytes: u64,
}

/// Counts and sizes over every live paste, for the admin page, without loading any of them.
pub async fn totals(st: &AppState, now: i64) -> Result<Totals, Error> {
    let pastes = sqlx::query!(
        r#"SELECT COUNT(*) AS "pastes!: i64", COALESCE(SUM(length(content)), 0) AS "content_bytes!: i64"
           FROM pastes
           WHERE burned_at IS NULL AND (expires_at IS NULL OR expires_at > ?)"#,
        now,
    )
    .fetch_one(&st.pool)
    .await?;
    let file_bytes = sqlx::query_scalar!(
        r#"SELECT COALESCE(SUM(f.size), 0) AS "file_bytes!: i64"
           FROM paste_files f JOIN pastes p ON p.id = f.paste_id
           WHERE p.burned_at IS NULL AND (p.expires_at IS NULL OR p.expires_at > ?)"#,
        now,
    )
    .fetch_one(&st.pool)
    .await?;
    let count = |n: i64| u64::try_from(n).map_err(Error::internal);
    Ok(Totals {
        pastes: count(pastes.pastes)?,
        content_bytes: count(pastes.content_bytes)?,
        file_bytes: count(file_bytes)?,
    })
}

/// Removes expired rows and rows burned more than [`BURNED_TTL_SECS`] ago, with their files.
/// Returns how many rows went.
pub async fn purge(st: &AppState, now: i64) -> Result<u64, Error> {
    let burned_before = now.saturating_sub(BURNED_TTL_SECS);
    let ids = sqlx::query_scalar!(
        r#"DELETE FROM pastes
           WHERE (expires_at IS NOT NULL AND expires_at <= ?) OR (burned_at IS NOT NULL AND burned_at <= ?)
           RETURNING id AS "id!""#,
        now,
        burned_before,
    )
    .fetch_all(&st.pool)
    .await?;
    for id in ids.iter().filter_map(|id| u64::try_from(*id).ok()) {
        // A leftover directory must not stop the rest of the purge; start-up removes orphans.
        if let Err(e) = remove_files(st, PasteId(id)).await {
            tracing::warn!(error = %e, "could not remove a purged paste's files");
        }
    }
    Ok(u64::try_from(ids.len()).unwrap_or(u64::MAX))
}
