//! Attachments: staged while the upload streams in, committed to `files/<id>/<position>`, and
//! streamed back out, decrypting private files on the way.
//!
//! Bytes are never stored under a user-supplied name: the path is always the paste ID and the
//! file's position. The sanitised name lives only in `paste_files`.

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::io;
use std::path::{Path, PathBuf};

use async_zip::base::write::ZipFileWriter;
use async_zip::{Compression, ZipDateTime, ZipDateTimeBuilder, ZipEntryBuilder};
use axum::body::Body;
use bytes::Bytes;
use futures_util::{Stream, StreamExt, future, stream};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter, DuplexStream};
use tokio::task::JoinHandle;
use tokio_util::compat::FuturesAsyncWriteCompatExt;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::domain::Privacy;
use crate::domain::crypto::{self, CHUNK_LEN, Dek, random_bytes};
use crate::domain::paste::Paste;
use crate::domain::words::PasteId;
use crate::error::Error;
use crate::state::AppState;

/// The type of every secret file and of any file whose type is unknown.
pub const PLACEHOLDER_MIME: &str = "application/octet-stream";
const STAGING_DIR: &str = ".staging";
/// More than a zip entry's headers and name take, twice over (the central directory repeats them).
const ZIP_ENTRY_OVERHEAD: u64 = 2048;
// Enough for any container header plus one tag, which is all the browser-container check reads.
const CONTAINER_HEAD_LEN: usize = 128;

/// One attachment as listed in `paste_files`. `size` counts plaintext bytes (secret: ciphertext).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    pub position: u32,
    pub name: String,
    pub size: u64,
    pub mime: String,
}

/// Uploads written to a private directory under `files/.staging/` until a paste claims them.
/// Dropping an uncommitted staging removes its directory, so every error path cleans up.
pub struct Staging {
    dir: PathBuf,
    dek: Option<Dek>,
    files: Vec<FileMeta>,
    committed: bool,
}

#[derive(Debug)]
struct OverLimit;

impl Display for OverLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("upload over its limit")
    }
}

impl std::error::Error for OverLimit {}

#[derive(Debug)]
struct Aborted(String);

impl Display for Aborted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upload aborted: {}", self.0)
    }
}

impl std::error::Error for Aborted {}

fn marker<T: std::error::Error + 'static>(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<T>())
}

impl Staging {
    /// A staging for plaintext files (public, unlisted, read-only, and secret containers).
    pub fn new(files_dir: &Path) -> Result<Self, Error> {
        Self::create(files_dir, None)
    }

    /// A staging that encrypts every file under a fresh data key, which becomes the paste's.
    pub fn new_private(files_dir: &Path) -> Result<Self, Error> {
        Self::create(files_dir, Some(Dek::random()))
    }

    fn create(files_dir: &Path, dek: Option<Dek>) -> Result<Self, Error> {
        let root = files_dir.join(STAGING_DIR);
        std::fs::create_dir_all(&root)?;
        let dir = root.join(hex::encode(random_bytes::<16>()));
        std::fs::create_dir(&dir)?;
        Ok(Self { dir, dek, files: Vec::new(), committed: false })
    }

    pub fn dek(&self) -> Option<&Dek> {
        self.dek.as_ref()
    }

    pub fn files(&self) -> &[FileMeta] {
        &self.files
    }

    /// Bytes staged so far, as counted against the limits.
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    /// Streams one file to disk, encrypting it when the staging has a data key. An empty `name`
    /// stores the placeholder `file-N` with [`PLACEHOLDER_MIME`]. More than `limit` bytes is
    /// `TooLarge`; an error from `body` is `Invalid`. A failed file leaves nothing behind.
    pub async fn add<S, E>(&mut self, name: &str, mime: &str, body: S, limit: u64) -> Result<FileMeta, Error>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: Display,
    {
        let position = u32::try_from(self.files.len() + 1).map_err(|_| Error::TooLarge)?;
        let (name, mime) = if name.is_empty() {
            (placeholder(position), PLACEHOLDER_MIME.to_owned())
        } else {
            let name = display_name(name, position);
            let mime = file_mime(&name, mime);
            (name, mime)
        };
        let path = self.dir.join(position.to_string());
        match self.write(&path, body, limit).await {
            Ok(size) => {
                let meta = FileMeta { position, name, size, mime };
                self.files.push(meta.clone());
                Ok(meta)
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(&path).await;
                Err(e)
            }
        }
    }

    /// Stages a secret paste's file: a browser container stored as-is under a placeholder name,
    /// refused unless its header is full-strength.
    pub async fn add_container<S, E>(&mut self, body: S, limit: u64) -> Result<FileMeta, Error>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: Display,
    {
        if self.dek.is_some() {
            return Err(Error::internal("secret containers cannot go into an encrypting staging"));
        }
        let meta = self.add("", "", body, limit).await?;
        let path = self.dir.join(meta.position.to_string());
        if let Err(e) = check_container(&path).await {
            let _ = tokio::fs::remove_file(&path).await;
            self.files.pop();
            return Err(e);
        }
        Ok(meta)
    }

    async fn write<S, E>(&self, path: &Path, body: S, limit: u64) -> Result<u64, Error>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: Display,
    {
        let file = tokio::fs::OpenOptions::new().write(true).create_new(true).open(path).await?;
        let mut out = BufWriter::new(file);
        let mut seen = 0u64;
        let counted = body.map(move |item| match item {
            Ok(chunk) => {
                seen = seen.saturating_add(chunk.len() as u64);
                if seen > limit { Err(io::Error::other(OverLimit)) } else { Ok(chunk) }
            }
            Err(e) => Err(io::Error::other(Aborted(e.to_string()))),
        });
        let mut reader = StreamReader::new(counted);
        let written = match &self.dek {
            Some(dek) => crypto::seal_stream(dek, &mut reader, &mut out).await,
            None => {
                async {
                    let n = tokio::io::copy(&mut reader, &mut out).await?;
                    out.flush().await?;
                    Ok(n)
                }
                .await
            }
        };
        match written {
            Err(Error::Io(e)) if marker::<OverLimit>(&e) => Err(Error::TooLarge),
            Err(Error::Io(e)) if marker::<Aborted>(&e) => {
                tracing::debug!(error = %e, "upload stream failed");
                Err(Error::Invalid("The upload did not finish. Try again.".into()))
            }
            other => other,
        }
    }

    /// Moves the staged files to `target`, which belongs to a paste row that was just inserted,
    /// so anything already there is an orphan of an earlier paste with the same ID.
    pub(crate) async fn commit(&mut self, target: &Path) -> Result<(), Error> {
        match tokio::fs::remove_dir_all(target).await {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        tokio::fs::rename(&self.dir, target).await?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Synchronous on purpose: a staging holds a handful of files, and callers (and tests)
        // rely on the directory being gone once the staging is.
        if let Err(e) = std::fs::remove_dir_all(&self.dir)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(error = %e, "could not remove a staging directory");
        }
    }
}

fn placeholder(position: u32) -> String {
    format!("file-{position}")
}

/// The last path component, with characters that are unsafe in file names or headers replaced
/// by `_`; whitespace becomes `_` too. Falls back to `file-N` when nothing usable is left.
fn display_name(raw: &str, position: u32) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    // Bidirectional controls can disguise an extension ("txt.exe" shown as "exe.txt").
    let base: String = base
        .chars()
        .map(|c| {
            let bidi = matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
            if bidi || c.is_whitespace() || c.is_control() { '_' } else { c }
        })
        .collect();
    let opts = sanitize_filename::Options { windows: true, truncate: true, replacement: "_" };
    let clean = sanitize_filename::sanitize_with_options(&base, opts);
    if clean.trim_matches(['_', '.']).is_empty() { placeholder(position) } else { clean }
}

/// The type implied by the name, else the uploader's claimed type if well-formed, else the placeholder.
fn file_mime(name: &str, claimed: &str) -> String {
    if let Some(m) = mime_guess::from_path(name).first() {
        return m.essence_str().to_owned();
    }
    claimed
        .parse::<mime_guess::mime::Mime>()
        .map(|m| m.essence_str().to_ascii_lowercase())
        .unwrap_or_else(|_| PLACEHOLDER_MIME.to_owned())
}

async fn check_container(path: &Path) -> Result<(), Error> {
    let mut head = Vec::with_capacity(CONTAINER_HEAD_LEN);
    File::open(path).await?.take(CONTAINER_HEAD_LEN as u64).read_to_end(&mut head).await?;
    crypto::check_browser_container(&head)
}

/// Where a paste's files live.
pub(crate) fn dir(st: &AppState, id: PasteId) -> PathBuf {
    st.files_dir.join(id.0.to_string())
}

fn db_id(id: PasteId) -> i64 {
    // IDs are below 2^33, so this never saturates.
    i64::try_from(id.0).unwrap_or(i64::MAX)
}

struct FileRow {
    position: i64,
    name: String,
    size: i64,
    mime: String,
}

impl TryFrom<FileRow> for FileMeta {
    type Error = Error;

    fn try_from(r: FileRow) -> Result<Self, Error> {
        Ok(Self {
            position: u32::try_from(r.position).map_err(Error::internal)?,
            size: u64::try_from(r.size).map_err(Error::internal)?,
            name: r.name,
            mime: r.mime,
        })
    }
}

/// A paste's files in position order.
pub(crate) async fn list(st: &AppState, id: PasteId) -> Result<Vec<FileMeta>, Error> {
    let db = db_id(id);
    let rows = sqlx::query_as!(
        FileRow,
        r#"SELECT position AS "position!", name AS "name!", size AS "size!", mime AS "mime!"
           FROM paste_files WHERE paste_id = ? ORDER BY position"#,
        db,
    )
    .fetch_all(&st.pool)
    .await?;
    rows.into_iter().map(FileMeta::try_from).collect()
}

/// The files of every paste in `ids`, in one query, each paste's in position order. Pastes
/// without files are absent from the map.
pub(crate) async fn list_for(st: &AppState, ids: &[PasteId]) -> Result<HashMap<PasteId, Vec<FileMeta>>, Error> {
    let mut out: HashMap<PasteId, Vec<FileMeta>> = HashMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    // A JSON array keeps it one statement for any number of pastes.
    let ids_json =
        serde_json::to_string(&ids.iter().map(|id| db_id(*id)).collect::<Vec<_>>()).map_err(Error::internal)?;
    let rows = sqlx::query!(
        r#"SELECT paste_id AS "paste_id!", position AS "position!", name AS "name!", size AS "size!", mime AS "mime!"
           FROM paste_files WHERE paste_id IN (SELECT value FROM json_each(?))
           ORDER BY paste_id, position"#,
        ids_json,
    )
    .fetch_all(&st.pool)
    .await?;
    for r in rows {
        let id = PasteId(u64::try_from(r.paste_id).map_err(Error::internal)?);
        let meta = FileMeta::try_from(FileRow { position: r.position, name: r.name, size: r.size, mime: r.mime })?;
        out.entry(id).or_default().push(meta);
    }
    Ok(out)
}

/// The data key to decrypt with: required for private pastes, ignored for every other level.
fn key_for(privacy: Privacy, dek: Option<&Dek>) -> Result<Option<Dek>, Error> {
    if privacy != Privacy::Private {
        return Ok(None);
    }
    let dek = dek.ok_or(Error::PasswordRequired)?;
    Dek::from_slice(dek.as_bytes()).map(Some).ok_or_else(|| Error::internal("a data key has the wrong length"))
}

/// One file of `p`: its metadata and a streamed body. Access rules (grants, burning, expiry)
/// are the caller's, who loaded `p` under them; this only needs the data key for a private
/// paste. A body whose bytes fail to decrypt ends in an error, never cleanly.
pub async fn open(st: &AppState, p: &Paste, position: u32, dek: Option<&Dek>) -> Result<(FileMeta, Body), Error> {
    let meta = p.files.iter().find(|f| f.position == position).cloned().ok_or(Error::NotFound)?;
    let key = key_for(p.privacy, dek)?;
    let file = File::open(dir(st, p.id).join(position.to_string())).await?;
    let body = match key {
        None => Body::from_stream(ReaderStream::with_capacity(file, CHUNK_LEN)),
        Some(key) => {
            let (reader, writer) = tokio::io::duplex(CHUNK_LEN);
            let task =
                tokio::spawn(async move { crypto::open_stream(&key, BufReader::new(file), writer).await.map(|_| ()) });
            piped(reader, task)
        }
    };
    Ok((meta, body))
}

/// The bytes `start..=end` of a file stored as-is (public levels and secret containers), read
/// by seeking, so nothing before `start` or after `end` is touched. Access rules are the
/// caller's, as for [`open`]; the caller has checked the range against the file's size.
pub async fn open_range(st: &AppState, id: PasteId, position: u32, start: u64, end: u64) -> Result<Body, Error> {
    let mut file = File::open(dir(st, id).join(position.to_string())).await?;
    file.seek(io::SeekFrom::Start(start)).await?;
    let len = end.saturating_sub(start).saturating_add(1);
    Ok(Body::from_stream(ReaderStream::with_capacity(file.take(len), CHUNK_LEN)))
}

/// Every file of `p` as a stored (uncompressed) zip, written while it streams out. Access rules
/// are the caller's, as for [`open`].
pub async fn zip(st: &AppState, p: &Paste, dek: Option<&Dek>) -> Result<Body, Error> {
    let metas = p.files.clone();
    let key = key_for(p.privacy, dek)?;
    let dir = dir(st, p.id);
    let stamp = zip_date(p.created_at);
    let (reader, writer) = tokio::io::duplex(CHUNK_LEN);
    let task = tokio::spawn(async move { write_zip(writer, &dir, metas, key, stamp).await });
    Ok(piped(reader, task))
}

/// A Unix time as a zip entry's date, in UTC. Zip dates start in 1980 and an entry without one
/// reads as the invalid day 1980-00-00.
fn zip_date(ts: i64) -> ZipDateTime {
    let t = time::OffsetDateTime::from_unix_timestamp(ts).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    ZipDateTimeBuilder::new()
        .year(t.year().clamp(1980, 2107))
        .month(u32::from(u8::from(t.month())))
        .day(u32::from(t.day()))
        .hour(u32::from(t.hour()))
        .minute(u32::from(t.minute()))
        .second(u32::from(t.second()))
        .build()
}

async fn write_zip(
    w: DuplexStream,
    dir: &Path,
    metas: Vec<FileMeta>,
    key: Option<Dek>,
    stamp: ZipDateTime,
) -> Result<(), Error> {
    let mut zip = ZipFileWriter::with_tokio(w);
    // async_zip ends a streamed zip64 entry with its sizes in the 32-bit form, which Info-ZIP's
    // unzip reports as an error after extracting. An archive that fits the classic format is
    // written in it; only one of 4 GiB or more needs zip64 and keeps that flaw.
    let total = metas.iter().fold(0u64, |sum, f| sum.saturating_add(f.size).saturating_add(ZIP_ENTRY_OVERHEAD));
    if total < u64::from(u32::MAX) {
        zip = zip.force_no_zip64();
    }
    let mut used = HashSet::new();
    for f in metas {
        // A repeated name would overwrite the earlier file on extraction.
        let mut name = f.name.clone();
        while used.contains(&name) {
            name = format!("{}-{name}", f.position);
        }
        used.insert(name.clone());
        // The entries say they come from Unix, where a mode of 0 extracts as a file nobody can read.
        let entry = ZipEntryBuilder::new(name.into(), Compression::Stored)
            .unix_permissions(0o644)
            .last_modification_date(stamp);
        let mut out = zip.write_entry_stream(entry).await.map_err(Error::internal)?.compat_write();
        let file = BufReader::new(File::open(dir.join(f.position.to_string())).await?);
        match &key {
            Some(key) => {
                crypto::open_stream(key, file, &mut out).await?;
            }
            None => {
                let mut file = file;
                tokio::io::copy(&mut file, &mut out).await?;
            }
        }
        out.into_inner().close().await.map_err(Error::internal)?;
    }
    zip.close().await.map_err(Error::internal)?;
    Ok(())
}

/// Streams what `task` writes into the pipe, then fails the body if the task failed, so a
/// client sees a broken transfer rather than a complete-looking but cut-off file.
fn piped(reader: DuplexStream, task: JoinHandle<Result<(), Error>>) -> Body {
    let outcome = stream::once(async move {
        let failure = match task.await {
            Ok(Ok(())) => return None,
            Ok(Err(e)) => format!("{e:?}"),
            Err(e) => e.to_string(),
        };
        tracing::error!(detail = %failure, "a file download failed part-way");
        Some(Err(io::Error::other("the download failed part-way")))
    })
    .filter_map(future::ready);
    Body::from_stream(ReaderStream::with_capacity(reader, CHUNK_LEN).chain(outcome))
}

/// Removes file directories without a paste row and any leftover staging, before serving.
/// Returns how many paste directories went.
pub async fn remove_orphans(st: &AppState) -> Result<u64, Error> {
    match tokio::fs::remove_dir_all(st.files_dir.join(STAGING_DIR)).await {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let mut removed = 0u64;
    let mut entries = tokio::fs::read_dir(&st.files_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|n| n.parse::<u64>().ok().filter(|id| id.to_string() == n)) else {
            continue;
        };
        let db = i64::try_from(id).unwrap_or(i64::MAX);
        let exists = sqlx::query_scalar!(r#"SELECT EXISTS (SELECT 1 FROM pastes WHERE id = ?) AS "exists!: bool""#, db)
            .fetch_one(&st.pool)
            .await?;
        if exists {
            continue;
        }
        if entry.file_type().await?.is_dir() {
            tokio::fs::remove_dir_all(entry.path()).await?;
        } else {
            tokio::fs::remove_file(entry.path()).await?;
        }
        removed += 1;
    }
    if removed > 0 {
        tracing::info!(removed, "removed orphaned file directories");
    }
    Ok(removed)
}
