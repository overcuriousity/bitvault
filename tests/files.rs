#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{IpAddr, Ipv4Addr};

use axum::http::{StatusCode, header};
use bitvault::domain::crypto::{self, Dek, PBKDF2_ITERATIONS};
use bitvault::domain::expiry::Expiry;
use bitvault::domain::files::{self, FileMeta, Staging};
use bitvault::domain::paste::{self, Access, DeleteAuth, NewPaste, SecretParts};
use bitvault::domain::words;
use bitvault::domain::{Privacy, grant};
use bitvault::error::Error;
use bitvault::state::AppState;
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use http_body_util::BodyExt;
use support::body_text;

const NOW: i64 = 1_800_000_000;
const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const MIB: usize = 1 << 20;
const LIMIT: u64 = 64 << 20;
const SECRET_PASSWORD: &str = "correct horse battery staple";

fn new(content: &str, privacy: Privacy) -> NewPaste {
    NewPaste {
        content: content.into(),
        privacy,
        expiry: Expiry::Hour24,
        burn_after_reads: 0,
        syntax: None,
        editable: false,
        password: None,
        secret: None,
    }
}

/// Pseudo-random bytes, so ciphertext and plaintext never line up by accident.
fn bytes(len: usize, seed: u8) -> Vec<u8> {
    let mut x = u32::from(seed) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Feeds `data` in uneven chunks, the way a network body arrives.
fn body(data: &[u8]) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Unpin + use<> {
    let chunks: Vec<Result<Bytes, std::io::Error>> =
        data.chunks(10_007).map(|c| Ok(Bytes::copy_from_slice(c))).collect();
    stream::iter(chunks)
}

async fn collect(b: axum::body::Body) -> Result<Vec<u8>, axum::Error> {
    b.collect().await.map(|c| c.to_bytes().to_vec())
}

fn staging_entries(st: &AppState) -> usize {
    match std::fs::read_dir(st.files_dir.join(".staging")) {
        Ok(rd) => rd.count(),
        Err(_) => 0,
    }
}

async fn row_count(st: &AppState) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM pastes").fetch_one(&st.pool).await.unwrap()
}

fn secret_container(plain: &[u8], iterations: u32) -> Vec<u8> {
    crypto::seal_alg2_for_tests(SECRET_PASSWORD, &[9; 16], iterations, plain)
}

#[tokio::test]
async fn files_attached_to_a_public_paste_download_byte_for_byte() {
    let app = support::app().await;
    let originals = [bytes(10, 1), bytes(150_000, 2), Vec::new()];
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    let names = ["notes.txt", "../x y.txt", "empty.bin"];
    for (name, data) in names.iter().zip(&originals) {
        staging.add(name, "application/octet-stream", body(data), LIMIT).await.unwrap();
    }
    let id = paste::create(&app.st, new("with files", Privacy::Public), Some(staging), NOW).await.unwrap();

    let p = paste::meta(&app.st, id, NOW).await.unwrap();
    let stored: Vec<_> = p.files.iter().map(|f| (f.position, f.name.as_str(), f.size)).collect();
    assert_eq!(stored, vec![(1, "notes.txt", 10), (2, "x_y.txt", 150_000), (3, "empty.bin", 0)]);
    assert_eq!(p.files[0].mime, "text/plain");
    for (i, data) in originals.iter().enumerate() {
        let position = u32::try_from(i + 1).unwrap();
        let (meta, b) = files::open(&app.st, id, position, None).await.unwrap();
        assert_eq!(meta.position, position);
        assert_eq!(&collect(b).await.unwrap(), data);
        let on_disk = std::fs::read(app.st.files_dir.join(id.0.to_string()).join(position.to_string())).unwrap();
        assert_eq!(&on_disk, data);
    }
    assert!(matches!(files::open(&app.st, id, 4, None).await, Err(Error::NotFound)));
    let opened = paste::read(&app.st, id, Access::Anonymous, IP, NOW).await.unwrap();
    assert_eq!(opened.paste.files, p.files);
    assert_eq!(staging_entries(&app.st), 0);
}

#[tokio::test]
async fn private_files_are_encrypted_on_disk_and_decrypt_with_the_paste_key() {
    let app = support::app().await;
    let plain = bytes(200_000, 3);
    let mut staging = Staging::new_private(&app.st.files_dir).unwrap();
    assert!(staging.dek().is_some());
    let meta = staging.add("report.pdf", "application/pdf", body(&plain), LIMIT).await.unwrap();
    assert_eq!(meta.size, 200_000);
    let id = paste::create(
        &app.st,
        NewPaste { password: Some("pw".into()), ..new("", Privacy::Private) },
        Some(staging),
        NOW,
    )
    .await
    .unwrap();

    let on_disk = std::fs::read(app.st.files_dir.join(id.0.to_string()).join("1")).unwrap();
    assert_ne!(on_disk, plain);
    assert!(!on_disk.windows(64).any(|w| w == &plain[1000..1064]));

    let opened = paste::read(&app.st, id, Access::Password("pw".into()), IP, NOW).await.unwrap();
    let dek = grant::check(&app.st.grant_key, &opened.grant.unwrap(), id, NOW).unwrap().unwrap();
    let (meta, b) = files::open(&app.st, id, 1, Some(&dek)).await.unwrap();
    assert_eq!(meta.name, "report.pdf");
    assert_eq!(collect(b).await.unwrap(), plain);

    let zipped = collect(files::zip(&app.st, id, Some(&dek)).await.unwrap()).await.unwrap();
    assert_eq!(unzip(zipped).await, vec![("report.pdf".to_owned(), plain.clone())]);

    assert!(matches!(files::open(&app.st, id, 1, None).await, Err(Error::PasswordRequired)));
    // A wrong key fails the stream rather than ending it, so a client never mistakes it for the file.
    let (_, b) = files::open(&app.st, id, 1, Some(&Dek::random())).await.unwrap();
    assert!(collect(b).await.is_err());
    let z = files::zip(&app.st, id, Some(&Dek::random())).await.unwrap();
    assert!(collect(z).await.is_err());
}

#[tokio::test]
async fn a_secret_paste_stores_only_placeholder_file_names() {
    let app = support::app().await;
    let file = secret_container(b"the secret bytes", PBKDF2_ITERATIONS);
    let content = secret_container(br#"{"text":"hi","files":["holiday plans.txt"]}"#, PBKDF2_ITERATIONS);
    let salt = [5u8; 16];
    let verifier = crypto::browser_verifier(SECRET_PASSWORD, &salt);
    let res = app
        .post_multipart(
            "/",
            &[
                ("privacy", None, b"secret"),
                ("content_container", None, &content),
                ("verifier_salt", None, hex::encode(salt).as_bytes()),
                ("verifier", None, hex::encode(verifier).as_bytes()),
                ("file", Some("holiday plans.txt"), &file),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let id = words::parse(&support::created(&res).0).unwrap();
    let p = paste::meta(&app.st, id, bitvault::domain::now()).await.unwrap();
    assert_eq!(p.privacy, Privacy::Secret);
    assert_eq!(
        p.files,
        vec![FileMeta {
            position: 1,
            name: "file-1".into(),
            size: u64::try_from(file.len()).unwrap(),
            mime: "application/octet-stream".into()
        }]
    );
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM paste_files").fetch_all(&app.st.pool).await.unwrap();
    assert_eq!(names, vec!["file-1".to_owned()]);
    let (_, b) = files::open(&app.st, id, 1, None).await.unwrap();
    assert_eq!(collect(b).await.unwrap(), file);

    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    let meta = staging.add("", "text/html", body(b"x"), LIMIT).await.unwrap();
    assert_eq!((meta.name.as_str(), meta.mime.as_str()), ("file-1", "application/octet-stream"));
}

#[tokio::test]
async fn an_upload_over_the_limit_leaves_nothing_behind() {
    let app = support::app().await;
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging.add("a.txt", "text/plain", body(&bytes(1000, 4)), 1000).await.unwrap();
    let res = staging.add("b.txt", "text/plain", body(&bytes(1001, 5)), 1000).await;
    assert!(matches!(res, Err(Error::TooLarge)), "{res:?}");
    drop(staging);
    assert_eq!(staging_entries(&app.st), 0);
    assert_eq!(row_count(&app.st).await, 0);

    let small = support::app_with("[app]\nmax_file_mb = 1\n").await;
    let big = bytes(MIB + MIB / 2, 6);
    let res = small.post_multipart("/", &[("content", None, b"hi"), ("file", Some("big.bin"), &big)]).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(staging_entries(&small.st), 0);
    assert_eq!(row_count(&small.st).await, 0);

    // Without a Content-Length the body limit (2 MiB here) only trips mid-stream. Two large
    // text fields use most of it, so it trips inside a file still under the 1 MiB file budget.
    let b = support::BOUNDARY;
    let mut multipart = Vec::new();
    for name in ["content", "notes"] {
        multipart
            .extend_from_slice(format!("--{b}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes());
        multipart.extend_from_slice(&vec![b'a'; MIB - 50_000]);
        multipart.extend_from_slice(b"\r\n");
    }
    multipart.extend_from_slice(
        format!("--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n\r\n").as_bytes(),
    );
    multipart.extend_from_slice(&bytes(MIB / 2, 12));
    multipart.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
    // Yielding between chunks makes the parser see the body arrive piece by piece, as from a socket.
    let trickle = body(&multipart).then(|chunk| async {
        tokio::task::yield_now().await;
        chunk
    });
    let chunked = axum::body::Body::from_stream(trickle);
    let r = small
        .req("POST", "/")
        .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={}", support::BOUNDARY))
        .body(chunked)
        .unwrap();
    assert_eq!(small.send(r).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(staging_entries(&small.st), 0);
    assert_eq!(row_count(&small.st).await, 0);

    let long = vec![b'a'; MIB + 1];
    let res = app.post_multipart("/", &[("content", None, &long)]).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(row_count(&app.st).await, 0);
}

#[tokio::test]
async fn an_aborted_upload_leaves_nothing_behind() {
    let app = support::app().await;
    for private in [false, true] {
        let mut staging = if private {
            Staging::new_private(&app.st.files_dir).unwrap()
        } else {
            Staging::new(&app.st.files_dir).unwrap()
        };
        let aborted = body(&bytes(MIB, 7)).chain(stream::iter([Err(std::io::Error::other("connection reset"))]));
        let res = staging.add("a.bin", "application/octet-stream", aborted, LIMIT).await;
        assert!(res.is_err());
        drop(staging);
        assert_eq!(staging_entries(&app.st), 0);
    }
    assert_eq!(row_count(&app.st).await, 0);
}

#[tokio::test]
async fn a_failed_commit_removes_the_row_and_the_staged_files() {
    let app = support::app().await;
    let paste_dirs = |st: &AppState| {
        std::fs::read_dir(&st.files_dir).unwrap().filter(|e| e.as_ref().unwrap().file_name() != ".staging").count()
    };
    // The staged directory vanishing before the move is a commit failure after the row went in.
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging.add("a.txt", "text/plain", body(b"abc"), LIMIT).await.unwrap();
    std::fs::remove_dir_all(app.st.files_dir.join(".staging")).unwrap();
    let res = paste::create(&app.st, new("x", Privacy::Public), Some(staging), NOW).await;
    assert!(matches!(res, Err(Error::Io(_))), "{res:?}");
    assert_eq!(row_count(&app.st).await, 0);
    let file_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM paste_files").fetch_one(&app.st.pool).await.unwrap();
    assert_eq!(file_rows, 0);
    assert_eq!(paste_dirs(&app.st), 0);

    // A plain staging cannot hold a private paste's files.
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging.add("a.txt", "text/plain", body(b"abc"), LIMIT).await.unwrap();
    let private = NewPaste { password: Some("pw".into()), ..new("x", Privacy::Private) };
    assert!(paste::create(&app.st, private, Some(staging), NOW).await.is_err());
    assert_eq!(staging_entries(&app.st), 0);
    assert_eq!(row_count(&app.st).await, 0);
    assert_eq!(paste_dirs(&app.st), 0);
}

#[tokio::test]
async fn deleting_a_paste_removes_its_files() {
    let app = support::app().await;
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging.add("a.txt", "text/plain", body(b"abc"), LIMIT).await.unwrap();
    let id = paste::create(&app.st, new("bye", Privacy::Public), Some(staging), NOW).await.unwrap();
    let dir = app.st.files_dir.join(id.0.to_string());
    assert!(dir.join("1").exists());
    paste::delete(&app.st, id, DeleteAuth::None, IP, NOW).await.unwrap();
    assert!(!dir.exists());
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM paste_files").fetch_one(&app.st.pool).await.unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn a_file_only_paste_is_valid_but_an_empty_one_is_not() {
    let app = support::app().await;
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging.add("a.txt", "text/plain", body(b"abc"), LIMIT).await.unwrap();
    paste::create(&app.st, new("", Privacy::Unlisted), Some(staging), NOW).await.unwrap();
    let empty = Staging::new(&app.st.files_dir).unwrap();
    let res = paste::create(&app.st, new(" ", Privacy::Unlisted), Some(empty), NOW).await;
    assert!(matches!(res, Err(Error::Invalid(_))));

    let res = app.post_multipart("/", &[("content", None, b""), ("file", Some("a.txt"), b"abc")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    // A browser sends an unnamed, empty part when no file was chosen; it is not an attachment.
    let res = app.post_multipart("/", &[("content", None, b""), ("file", Some(""), b"")]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// async_zip's replacement reader (`read1`) has no in-memory reader yet.
#[allow(deprecated)]
async fn unzip(data: Vec<u8>) -> Vec<(String, Vec<u8>)> {
    let reader = async_zip::base::read::mem::ZipFileReader::new(data).await.unwrap();
    let mut out = Vec::new();
    for i in 0..reader.file().entries().len() {
        let mut entry = reader.reader_with_entry(i).await.unwrap();
        let name = entry.entry().filename().as_str().unwrap().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end_checked(&mut bytes).await.unwrap();
        out.push((name, bytes));
    }
    out
}

#[tokio::test]
async fn the_zip_contains_every_file() {
    let app = support::app().await;
    let originals = [("a.txt", bytes(10, 8)), ("b.bin", bytes(300_000, 9)), ("a.txt", bytes(20, 10))];
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    for (name, data) in &originals {
        staging.add(name, "application/octet-stream", body(data), LIMIT).await.unwrap();
    }
    let id = paste::create(&app.st, new("zipped", Privacy::Public), Some(staging), NOW).await.unwrap();
    let zipped = collect(files::zip(&app.st, id, None).await.unwrap()).await.unwrap();
    let entries = unzip(zipped).await;
    let expected: Vec<(String, Vec<u8>)> = vec![
        ("a.txt".into(), originals[0].1.clone()),
        ("b.bin".into(), originals[1].1.clone()),
        // A repeated name would overwrite the first file on extraction.
        ("3-a.txt".into(), originals[2].1.clone()),
    ];
    assert_eq!(entries, expected);
}

#[tokio::test]
async fn the_create_route_accepts_bodies_larger_than_one_mebibyte() {
    let app = support::app().await;
    let file = bytes(3 * MIB, 11);
    let res = app
        .post_multipart(
            "/",
            &[("content", None, b"big one"), ("privacy", None, b"unlisted"), ("file", Some("big.bin"), &file)],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let id = words::parse(&support::created(&res).0).unwrap();
    let (meta, b) = files::open(&app.st, id, 1, None).await.unwrap();
    assert_eq!(meta.size, u64::try_from(file.len()).unwrap());
    assert_eq!(collect(b).await.unwrap(), file);
}

#[tokio::test]
async fn the_create_form_stores_every_field() {
    let app = support::app_with("[app]\neditable = true\n").await;
    let res = app
        .post_multipart(
            "/",
            &[
                ("content", None, b"fn main() {}"),
                ("privacy", None, b"readonly"),
                ("password", None, b"pw"),
                ("expiry", None, b"1hour"),
                ("burn_after_reads", None, b"3"),
                ("syntax", None, b"rs"),
                ("editable", None, b"on"),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let id = words::parse(&support::created(&res).0).unwrap();
    let p = paste::meta(&app.st, id, bitvault::domain::now()).await.unwrap();
    assert_eq!(p.privacy, Privacy::Readonly);
    assert_eq!(p.syntax.as_deref(), Some("rs"));
    assert!(p.editable);
    assert_eq!(p.burn_after_reads, 3);
    assert_eq!(p.expires_at.map(|e| e - p.created_at), Some(3600));
    assert!(p.password_hash.is_some());

    let res = app.post_multipart("/", &[("content", None, b"x"), ("syntax", None, b"no-such-language")]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let res = app.post_multipart("/", &[("content", None, b"x"), ("privacy", None, b"everyone")]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let res = app
        .post_multipart("/", &[("content", None, b"x"), ("file", Some("a.txt"), b"abc"), ("privacy", None, b"private")])
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(staging_entries(&app.st), 0);
}

#[tokio::test]
async fn a_weak_secret_container_posted_to_the_form_is_refused() {
    let app = support::app().await;
    let salt = [5u8; 16];
    let verifier = hex::encode(crypto::browser_verifier(SECRET_PASSWORD, &salt));
    let strong = secret_container(br#"{"text":"hi","files":["a"]}"#, PBKDF2_ITERATIONS);
    let weak = secret_container(br#"{"text":"hi","files":["a"]}"#, 1000);
    let post = |content: Vec<u8>, file: Vec<u8>| {
        let (salt, verifier) = (hex::encode(salt), verifier.clone());
        let app = &app;
        async move {
            app.post_multipart(
                "/",
                &[
                    ("privacy", None, b"secret"),
                    ("content_container", None, &content),
                    ("verifier_salt", None, salt.as_bytes()),
                    ("verifier", None, verifier.as_bytes()),
                    ("file", Some("blob"), &file),
                ],
            )
            .await
            .status()
        }
    };
    assert_eq!(post(weak.clone(), strong.clone()).await, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(post(strong.clone(), weak.clone()).await, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(post(strong.clone(), b"not a container".to_vec()).await, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(staging_entries(&app.st), 0);
    assert_eq!(row_count(&app.st).await, 0);
    assert_eq!(post(strong.clone(), strong.clone()).await, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn the_uploader_password_is_checked_before_any_file_is_stored() {
    let app = support::app_with("[app]\nuploader_password = \"letmein\"\n").await;
    for parts in [
        vec![("content", None, &b"x"[..])],
        vec![("uploader_password", None, &b"wrong"[..]), ("content", None, &b"x"[..])],
        vec![
            ("content", None, &b"x"[..]),
            ("file", Some("a.txt"), &b"abc"[..]),
            ("uploader_password", None, &b"letmein"[..]),
        ],
    ] {
        let res = app.post_multipart("/", &parts).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert!(body_text(res).await.contains("Enter the uploader password to create pastes."));
    }
    assert_eq!(staging_entries(&app.st), 0);
    assert_eq!(row_count(&app.st).await, 0);
    let res = app
        .post_multipart(
            "/",
            &[("uploader_password", None, b"letmein"), ("content", None, b"x"), ("file", Some("a.txt"), b"abc")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn creating_is_rate_limited_per_address() {
    let app = support::app().await;
    for _ in 0..10 {
        assert_eq!(app.post_multipart("/", &[("content", None, b"x")]).await.status(), StatusCode::SEE_OTHER);
    }
    assert_eq!(app.post_multipart("/", &[("content", None, b"x")]).await.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn orphaned_file_dirs_are_removed_at_start_up() {
    let app = support::app().await;
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging.add("a.txt", "text/plain", body(b"abc"), LIMIT).await.unwrap();
    let id = paste::create(&app.st, new("kept", Privacy::Public), Some(staging), NOW).await.unwrap();
    let orphan = app.st.files_dir.join("12345");
    std::fs::create_dir_all(&orphan).unwrap();
    std::fs::write(orphan.join("1"), b"left over").unwrap();
    let stale = app.st.files_dir.join(".staging").join("deadbeef");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("1"), b"half an upload").unwrap();

    let _rebuilt = bitvault::app::build((*app.st.cfg).clone(), app.st.pool.clone()).await.unwrap();
    assert!(!orphan.exists());
    assert!(!stale.exists());
    assert!(app.st.files_dir.join(id.0.to_string()).join("1").is_file());
}

#[tokio::test]
async fn a_secret_paste_needs_its_parts_and_files_keep_their_container() {
    let app = support::app().await;
    let file = secret_container(b"payload", PBKDF2_ITERATIONS);
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging.add_container(body(&file), LIMIT).await.unwrap();
    let salt = [1u8; 16];
    let new = NewPaste {
        secret: Some(SecretParts {
            container: secret_container(br#"{"text":"","files":["a"]}"#, PBKDF2_ITERATIONS),
            verifier_salt: salt,
            verifier: crypto::browser_verifier(SECRET_PASSWORD, &salt),
        }),
        ..new("", Privacy::Secret)
    };
    let id = paste::create(&app.st, new, Some(staging), NOW).await.unwrap();
    let p = paste::meta(&app.st, id, NOW).await.unwrap();
    assert_eq!(p.files[0].name, "file-1");

    let mut weak = Staging::new(&app.st.files_dir).unwrap();
    let res = weak.add_container(body(&secret_container(b"x", 1000)), LIMIT).await;
    assert!(matches!(res, Err(Error::UnsupportedFormat)));
}

fn status_of(res: axum::http::Response<axum::body::Body>) -> StatusCode {
    res.status()
}

#[tokio::test]
async fn part_headers_that_never_end_are_refused() {
    let app = support::app().await;
    let b = support::BOUNDARY;
    let junk = vec![b'a'; 4 * MIB];
    let first_part =
        [format!("--{b}\r\nContent-Disposition: form-data; name=\"x\"\r\nX-Junk: ").as_bytes(), &junk].concat();
    let second_part = [
        support::multipart_parts(&[("content", None, b"hi")]).as_slice(),
        format!("--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\nX-Junk: ").as_bytes(),
        &junk,
    ]
    .concat();
    let headerless = [format!("--{b}\r\n\r\n").as_bytes(), &junk].concat();
    let preamble = junk.clone();
    for body in [first_part, second_part, headerless, preamble] {
        let res = app.post_multipart_body("/", axum::body::Body::from(body)).await;
        assert_eq!(status_of(res), StatusCode::PAYLOAD_TOO_LARGE);
    }
    assert_eq!(staging_entries(&app.st), 0);
    assert_eq!(row_count(&app.st).await, 0);
}

#[tokio::test]
async fn a_form_split_into_tiny_chunks_still_parses() {
    let app = support::app().await;
    let file = bytes(200_000, 13);
    let encoded = support::multipart_body(&[
        ("content", None, b"split"),
        ("privacy", None, b"public"),
        ("file", Some("a.bin"), &file),
        ("file", Some("b.txt"), b"second"),
    ]);
    let chunks: Vec<Result<Bytes, std::io::Error>> = encoded.chunks(7).map(|c| Ok(Bytes::copy_from_slice(c))).collect();
    let trickle = stream::iter(chunks).then(|chunk| async {
        tokio::task::yield_now().await;
        chunk
    });
    let res = app.post_multipart_body("/", axum::body::Body::from_stream(trickle)).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let id = words::parse(&support::created(&res).0).unwrap();
    let (_, b) = files::open(&app.st, id, 1, None).await.unwrap();
    assert_eq!(collect(b).await.unwrap(), file);
    let (meta, b) = files::open(&app.st, id, 2, None).await.unwrap();
    assert_eq!(meta.name, "b.txt");
    assert_eq!(collect(b).await.unwrap(), b"second");
}

async fn post_secret(app: &support::App, content: &[u8], file: &[u8]) -> StatusCode {
    let salt = [5u8; 16];
    let verifier = hex::encode(crypto::browser_verifier(SECRET_PASSWORD, &salt));
    app.post_multipart(
        "/",
        &[
            ("privacy", None, b"secret"),
            ("content_container", None, content),
            ("verifier_salt", None, hex::encode(salt).as_bytes()),
            ("verifier", None, verifier.as_bytes()),
            ("file", Some("blob"), file),
        ],
    )
    .await
    .status()
}

#[tokio::test]
async fn secret_limits_allow_for_the_container_overhead() {
    let app = support::app_with("[app]\nmax_secret_file_mb = 1\n").await;
    let content = secret_container(br#"{"text":"","files":["a"]}"#, PBKDF2_ITERATIONS);
    let at_limit = secret_container(&bytes(MIB, 14), PBKDF2_ITERATIONS);
    assert_eq!(post_secret(&app, &content, &at_limit).await, StatusCode::SEE_OTHER);
    let over = secret_container(&bytes(MIB + (64 << 10), 15), PBKDF2_ITERATIONS);
    assert_eq!(post_secret(&app, &content, &over).await, StatusCode::PAYLOAD_TOO_LARGE);

    // A megabyte of text can grow sixfold as JSON (control characters become \u00XX).
    let escaped = format!(r#"{{"text":"{}","files":["a"]}}"#, "\\u0001".repeat(MIB));
    let big_content = secret_container(escaped.as_bytes(), PBKDF2_ITERATIONS);
    let file = secret_container(b"x", PBKDF2_ITERATIONS);
    assert_eq!(post_secret(&app, &big_content, &file).await, StatusCode::SEE_OTHER);
}

/// A body whose last file part never finishes: the request can only complete if the server
/// refuses the form before reading that file.
fn stalled_after(parts: &[(&str, Option<&str>, &[u8])]) -> axum::body::Body {
    let mut head = support::multipart_parts(parts);
    head.extend_from_slice(
        format!("--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n\r\n", support::BOUNDARY)
            .as_bytes(),
    );
    head.extend_from_slice(&bytes(100_000, 16));
    let s = stream::iter([Ok::<_, std::io::Error>(Bytes::from(head))]).chain(stream::pending());
    axum::body::Body::from_stream(s)
}

#[tokio::test]
async fn a_refused_level_or_container_stops_the_form_before_any_file() {
    let app = support::app_with("[app]\nprivacy_levels = [\"public\", \"unlisted\", \"secret\"]\n").await;
    let within = std::time::Duration::from_secs(10);
    let res = tokio::time::timeout(
        within,
        app.post_multipart_body("/", stalled_after(&[("content", None, b"x"), ("privacy", None, b"private")])),
    )
    .await
    .expect("the form is refused without waiting for the file");
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("That privacy level is not offered here."));

    let weak = secret_container(br#"{"text":"hi","files":["a"]}"#, 1000);
    let res = tokio::time::timeout(
        within,
        app.post_multipart_body(
            "/",
            stalled_after(&[("privacy", None, b"secret"), ("content_container", None, &weak)]),
        ),
    )
    .await
    .expect("the form is refused without waiting for the file");
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(staging_entries(&app.st), 0);
    assert_eq!(row_count(&app.st).await, 0);
}

#[tokio::test]
async fn a_file_part_without_a_filename_is_stored_under_a_placeholder() {
    let app = support::app().await;
    let res = app
        .post_multipart(
            "/",
            &[("content", None, b"x"), ("file", None, b"abc"), ("file", None, b""), ("file", Some("empty.txt"), b"")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let id = words::parse(&support::created(&res).0).unwrap();
    let p = paste::meta(&app.st, id, bitvault::domain::now()).await.unwrap();
    let stored: Vec<_> = p.files.iter().map(|f| (f.name.as_str(), f.size, f.mime.as_str())).collect();
    assert_eq!(stored, vec![("file-1", 3, "application/octet-stream"), ("empty.txt", 0, "text/plain")]);
}

#[tokio::test]
async fn lists_carry_each_pastes_files_and_content_size_without_the_content() {
    let app = support::app().await;
    let mut with_files = Staging::new(&app.st.files_dir).unwrap();
    with_files.add("a.txt", "", body(b"aaa"), LIMIT).await.unwrap();
    with_files.add("b.txt", "", body(b"bbbbb"), LIMIT).await.unwrap();
    let two = paste::create(&app.st, new("two files", Privacy::Public), Some(with_files), NOW).await.unwrap();
    let none = paste::create(&app.st, new("no files here", Privacy::Public), None, NOW + 1).await.unwrap();
    let mut one = Staging::new(&app.st.files_dir).unwrap();
    one.add("c.txt", "", body(b"c"), LIMIT).await.unwrap();
    let hidden = paste::create(&app.st, new("x", Privacy::Unlisted), Some(one), NOW + 2).await.unwrap();

    let listed = paste::list_public(&app.st, 1, NOW + 10).await.unwrap();
    assert_eq!(listed.iter().map(|p| p.id).collect::<Vec<_>>(), [none, two]);
    let names = |p: &paste::Paste| p.files.iter().map(|f| f.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&listed[1]), ["a.txt", "b.txt"]);
    assert!(listed[0].files.is_empty());
    assert_eq!((listed[0].content_len, listed[1].content_len), (13, 9));

    let all = paste::list_all(&app.st, NOW + 10).await.unwrap();
    assert_eq!(all.iter().map(|p| p.id).collect::<Vec<_>>(), [hidden, none, two]);
    assert_eq!(names(&all[0]), ["c.txt"]);
    assert_eq!(all[2].files.iter().map(|f| f.size).sum::<u64>(), 8);
}

#[tokio::test]
async fn downloads_and_zips_are_never_compressed_but_pages_are() {
    let app = support::app().await;
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging.add("data.bin", "", body(&bytes(64 << 10, 3)), LIMIT).await.unwrap();
    staging.add("photo.png", "image/png", body(&bytes(64 << 10, 4)), LIMIT).await.unwrap();
    let w = paste::create(&app.st, new(&"page text ".repeat(500), Privacy::Public), Some(staging), NOW)
        .await
        .unwrap()
        .words();
    let fetch = |uri: String| {
        let r = app.req("GET", &uri).header(header::ACCEPT_ENCODING, "gzip, br").body(axum::body::Body::empty());
        app.send(r.unwrap())
    };
    for uri in [format!("/{w}/file/1"), format!("/{w}/file/2"), format!("/{w}/zip")] {
        let res = fetch(uri.clone()).await;
        assert_eq!(res.status(), StatusCode::OK, "{uri}");
        assert!(res.headers().get(header::CONTENT_ENCODING).is_none(), "{uri} was compressed");
    }
    let page = fetch(format!("/{w}")).await;
    assert!(page.headers().get(header::CONTENT_ENCODING).is_some(), "the paste page should be compressed");
}

async fn range_get(app: &support::App, uri: &str, range: Option<&str>) -> axum::http::Response<axum::body::Body> {
    let mut r = app.req("GET", uri);
    if let Some(range) = range {
        r = r.header(header::RANGE, range);
    }
    app.send(r.body(axum::body::Body::empty()).unwrap()).await
}

fn head(res: &axum::http::Response<axum::body::Body>, name: header::HeaderName) -> Option<&str> {
    res.headers().get(name).and_then(|v| v.to_str().ok())
}

async fn public_file(app: &support::App, data: &[u8]) -> String {
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging.add("data.bin", "", body(data), LIMIT).await.unwrap();
    paste::create(&app.st, new("x", Privacy::Public), Some(staging), NOW).await.unwrap().words()
}

#[tokio::test]
async fn a_public_file_has_a_length_and_accepts_ranges() {
    let app = support::app().await;
    let data = bytes(1000, 5);
    let w = public_file(&app, &data).await;
    let res = range_get(&app, &format!("/{w}/file/1"), None).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(head(&res, header::CONTENT_LENGTH), Some("1000"));
    assert_eq!(head(&res, header::ACCEPT_RANGES), Some("bytes"));
    assert_eq!(head(&res, header::CACHE_CONTROL), Some("no-store"));
    assert_eq!(collect(res.into_body()).await.unwrap(), data);
}

#[tokio::test]
async fn single_ranges_send_exactly_the_requested_bytes() {
    let app = support::app().await;
    let data = bytes(1000, 6);
    let w = public_file(&app, &data).await;
    let uri = format!("/{w}/file/1");
    for (range, from, to) in
        [("bytes=0-9", 0, 9), ("bytes=-5", 995, 999), ("bytes=10-", 10, 999), ("bytes=990-5000", 990, 999)]
    {
        let res = range_get(&app, &uri, Some(range)).await;
        assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(head(&res, header::CONTENT_RANGE), Some(format!("bytes {from}-{to}/1000").as_str()), "{range}");
        assert_eq!(head(&res, header::CONTENT_LENGTH), Some((to - from + 1).to_string().as_str()), "{range}");
        assert_eq!(collect(res.into_body()).await.unwrap(), data[from..=to], "{range}");
    }
}

#[tokio::test]
async fn an_unsatisfiable_range_is_416_with_the_total() {
    let app = support::app().await;
    let w = public_file(&app, &bytes(100, 7)).await;
    for range in ["bytes=999999-", "bytes=100-120", "bytes=-0"] {
        let res = range_get(&app, &format!("/{w}/file/1"), Some(range)).await;
        assert_eq!(res.status(), StatusCode::RANGE_NOT_SATISFIABLE, "{range}");
        assert_eq!(head(&res, header::CONTENT_RANGE), Some("bytes */100"), "{range}");
    }
}

#[tokio::test]
async fn multi_range_and_malformed_ranges_get_the_full_body() {
    let app = support::app().await;
    let data = bytes(100, 8);
    let w = public_file(&app, &data).await;
    for range in ["bytes=0-1,5-6", "bytes=abc", "items=0-5", "bytes=5-2", "bytes=-"] {
        let res = range_get(&app, &format!("/{w}/file/1"), Some(range)).await;
        assert_eq!(res.status(), StatusCode::OK, "{range}");
        assert!(res.headers().get(header::CONTENT_RANGE).is_none(), "{range}");
        assert_eq!(collect(res.into_body()).await.unwrap(), data, "{range}");
    }
}

#[tokio::test]
async fn a_partial_response_is_not_compressed_and_head_has_no_body() {
    let app = support::app().await;
    let w = public_file(&app, &bytes(5000, 9)).await;
    let r = app
        .req("GET", &format!("/{w}/file/1"))
        .header(header::RANGE, "bytes=0-999")
        .header(header::ACCEPT_ENCODING, "gzip");
    let res = app.send(r.body(axum::body::Body::empty()).unwrap()).await;
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert!(res.headers().get(header::CONTENT_ENCODING).is_none());

    let res = app.send(app.req("HEAD", &format!("/{w}/file/1")).body(axum::body::Body::empty()).unwrap()).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(head(&res, header::CONTENT_LENGTH), Some("5000"));
    assert!(collect(res.into_body()).await.unwrap().is_empty());
}

#[tokio::test]
async fn private_files_have_a_plaintext_length_and_ignore_ranges() {
    let app = support::app().await;
    let plain = bytes(150_000, 10);
    let mut staging = Staging::new_private(&app.st.files_dir).unwrap();
    staging.add("p.bin", "", body(&plain), LIMIT).await.unwrap();
    let id = paste::create(
        &app.st,
        NewPaste { password: Some("pw".into()), ..new("", Privacy::Private) },
        Some(staging),
        domain_now(),
    )
    .await
    .unwrap();
    let opened = paste::read(&app.st, id, Access::Password("pw".into()), IP, domain_now()).await.unwrap();
    let uri = format!("/{}/file/1?g={}", id.words(), opened.grant.unwrap());
    let res = range_get(&app, &uri, Some("bytes=0-9")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(head(&res, header::CONTENT_LENGTH), Some("150000"));
    assert!(res.headers().get(header::ACCEPT_RANGES).is_none());
    assert!(res.headers().get(header::CONTENT_RANGE).is_none());
    assert_eq!(collect(res.into_body()).await.unwrap(), plain);
}

#[tokio::test]
async fn a_secret_container_is_served_with_a_length_and_ranges() {
    let app = support::app().await;
    let file = secret_container(b"payload", PBKDF2_ITERATIONS);
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging.add_container(body(&file), LIMIT).await.unwrap();
    let salt = [1u8; 16];
    let n = NewPaste {
        secret: Some(SecretParts {
            container: secret_container(br#"{"text":"","files":["a"]}"#, PBKDF2_ITERATIONS),
            verifier_salt: salt,
            verifier: crypto::browser_verifier(SECRET_PASSWORD, &salt),
        }),
        ..new("", Privacy::Secret)
    };
    let w = paste::create(&app.st, n, Some(staging), domain_now()).await.unwrap().words();
    let uri = format!("/{w}/file/1");
    let res = range_get(&app, &uri, None).await;
    assert_eq!(head(&res, header::CONTENT_LENGTH), Some(file.len().to_string().as_str()));
    let res = range_get(&app, &uri, Some("bytes=2-6")).await;
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(collect(res.into_body()).await.unwrap(), file[2..=6]);
}

fn domain_now() -> i64 {
    bitvault::domain::now()
}
