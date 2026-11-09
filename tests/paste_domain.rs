#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bitvault::domain::crypto::{self, PBKDF2_ITERATIONS};
use bitvault::domain::expiry::Expiry;
use bitvault::domain::paste::{self, Access, Body, DeleteAuth, NewPaste, SecretParts};
use bitvault::domain::words::PasteId;
use bitvault::domain::{Kind, Privacy};
use bitvault::error::Error;
use bitvault::state::AppState;

const NOW: i64 = 1_800_000_000;
const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const OTHER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

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

fn with_password(content: &str, privacy: Privacy, password: &str) -> NewPaste {
    NewPaste { password: Some(password.into()), ..new(content, privacy) }
}

async fn create(st: &AppState, p: NewPaste) -> PasteId {
    paste::create(st, p, None, NOW).await.unwrap()
}

async fn read(st: &AppState, id: PasteId, access: Access) -> Result<paste::Opened, Error> {
    paste::read(st, id, access, IP, NOW).await
}

fn text(body: &Body) -> &str {
    match body {
        Body::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    }
}

const SECRET_PASSWORD: &str = "correct horse battery staple";
const VERIFIER_SALT: [u8; 16] = [7; 16];

fn secret_paste(iterations: u32) -> NewPaste {
    let container = crypto::seal_alg2_for_tests(SECRET_PASSWORD, &[9; 16], iterations, br#"{"text":"hi","files":[]}"#);
    NewPaste {
        secret: Some(SecretParts {
            container,
            verifier_salt: VERIFIER_SALT,
            verifier: crypto::browser_verifier(SECRET_PASSWORD, &VERIFIER_SALT),
        }),
        ..new("", Privacy::Secret)
    }
}

/// The stored content bytes, read straight from the table.
async fn stored_content(st: &AppState, id: PasteId) -> Vec<u8> {
    sqlx::query_scalar("SELECT content FROM pastes WHERE id = ?").bind(id.0 as i64).fetch_one(&st.pool).await.unwrap()
}

async fn row_count(st: &AppState) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM pastes").fetch_one(&st.pool).await.unwrap()
}

#[tokio::test]
async fn a_public_text_paste_is_readable_and_listed() {
    let app = support::app().await;
    let id = create(&app.st, new("hello", Privacy::Public)).await;
    let opened = read(&app.st, id, Access::Anonymous).await.unwrap();
    assert_eq!(text(&opened.body), "hello");
    assert_eq!(opened.paste.kind, Kind::Text);
    assert!(opened.grant.is_none());
    let listed = paste::list_public(&app.st, 1, NOW).await.unwrap();
    assert_eq!(listed.iter().map(|p| p.id).collect::<Vec<_>>(), vec![id]);
}

#[tokio::test]
async fn unlisted_pastes_are_not_listed() {
    let app = support::app().await;
    let id = create(&app.st, new("hidden", Privacy::Unlisted)).await;
    assert!(paste::list_public(&app.st, 1, NOW).await.unwrap().is_empty());
    assert_eq!(text(&read(&app.st, id, Access::Anonymous).await.unwrap().body), "hidden");
}

#[tokio::test]
async fn the_public_list_is_newest_first_in_pages_of_fifty() {
    let app = support::app().await;
    for i in 0..51 {
        paste::create(&app.st, new(&format!("paste {i}"), Privacy::Public), None, NOW + i).await.unwrap();
    }
    let first = paste::list_public(&app.st, 1, NOW + 100).await.unwrap();
    let second = paste::list_public(&app.st, 2, NOW + 100).await.unwrap();
    assert_eq!(first.len(), 50);
    assert_eq!(first[0].created_at, NOW + 50);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].created_at, NOW);
}

#[tokio::test]
async fn a_whole_content_url_in_a_public_paste_becomes_a_redirect() {
    let app = support::app().await;
    let id = create(&app.st, new("  https://example.org/a?b=c  \n", Privacy::Public)).await;
    let opened = read(&app.st, id, Access::Anonymous).await.unwrap();
    assert_eq!(opened.paste.kind, Kind::Url);
    assert!(matches!(&opened.body, Body::Url(u) if u == "https://example.org/a?b=c"));
}

#[tokio::test]
async fn text_around_a_url_keeps_a_paste_as_text() {
    let app = support::app().await;
    let id = create(&app.st, new("see https://example.org", Privacy::Unlisted)).await;
    assert_eq!(read(&app.st, id, Access::Anonymous).await.unwrap().paste.kind, Kind::Text);
}

#[tokio::test]
async fn a_url_in_a_private_paste_stays_text() {
    let app = support::app().await;
    let id = create(&app.st, with_password("https://example.org", Privacy::Private, "pw")).await;
    let opened = read(&app.st, id, Access::Password("pw".into())).await.unwrap();
    assert_eq!(opened.paste.kind, Kind::Text);
    assert_eq!(text(&opened.body), "https://example.org");
}

#[tokio::test]
async fn a_private_paste_needs_its_password() {
    let app = support::app().await;
    let plain = "the launch codes are 0000";
    let id = create(&app.st, with_password(plain, Privacy::Private, "hunter2")).await;
    assert!(matches!(read(&app.st, id, Access::Anonymous).await, Err(Error::PasswordRequired)));
    assert!(matches!(read(&app.st, id, Access::Admin).await, Err(Error::PasswordRequired)));
    assert!(matches!(read(&app.st, id, Access::Password("wrong".into())).await, Err(Error::WrongPassword)));
    let opened = read(&app.st, id, Access::Password("hunter2".into())).await.unwrap();
    assert_eq!(text(&opened.body), plain);
    let stored = paste::meta(&app.st, id, NOW).await.unwrap();
    let content = stored_content(&app.st, id).await;
    assert_eq!(stored.content_len, content.len() as u64);
    assert!(!content.windows(plain.len()).any(|w| w == plain.as_bytes()));
    assert!(stored.wrapped_key.is_some());
    assert!(stored.password_hash.is_none());
}

#[tokio::test]
async fn an_unlock_returns_a_grant_that_opens_the_paste_again() {
    let app = support::app().await;
    let id = create(&app.st, with_password("granted", Privacy::Private, "pw")).await;
    let grant = read(&app.st, id, Access::Password("pw".into())).await.unwrap().grant.unwrap();
    let again = read(&app.st, id, Access::Grant(grant.clone())).await.unwrap();
    assert_eq!(text(&again.body), "granted");
    let other = create(&app.st, with_password("other", Privacy::Private, "pw")).await;
    assert!(matches!(read(&app.st, other, Access::Grant(grant)).await, Err(Error::Forbidden)));
    assert!(matches!(read(&app.st, id, Access::Grant("garbage".into())).await, Err(Error::Forbidden)));
}

#[tokio::test]
async fn wrong_passwords_are_rate_limited_but_right_ones_are_not() {
    let app = support::app().await;
    let id = create(&app.st, with_password("limited", Privacy::Private, "right")).await;
    for _ in 0..5 {
        assert!(matches!(read(&app.st, id, Access::Password("wrong".into())).await, Err(Error::WrongPassword)));
    }
    assert!(matches!(read(&app.st, id, Access::Password("right".into())).await, Err(Error::TooManyAttempts)));
    let elsewhere = paste::read(&app.st, id, Access::Password("right".into()), OTHER_IP, NOW).await.unwrap();
    assert_eq!(text(&elsewhere.body), "limited");
    for _ in 0..10 {
        paste::read(&app.st, id, Access::Password("right".into()), OTHER_IP, NOW).await.unwrap();
    }
}

#[tokio::test]
async fn right_passwords_used_again_and_again_are_never_limited() {
    let app = support::app_with("[app]\neditable = true\n").await;
    let private = create(&app.st, NewPaste { editable: true, ..with_password("p", Privacy::Private, "pw") }).await;
    let readonly = create(&app.st, NewPaste { editable: true, ..with_password("r", Privacy::Readonly, "pw") }).await;
    for _ in 0..8 {
        read(&app.st, private, Access::Password("pw".into())).await.unwrap();
        paste::edit(&app.st, readonly, Access::Password("pw".into()), IP, "r2".into(), None, NOW).await.unwrap();
    }
    paste::delete(&app.st, private, DeleteAuth::Password("pw".into()), IP, NOW).await.unwrap();
}

#[tokio::test]
async fn wrong_edit_passwords_are_rate_limited() {
    let app = support::app_with("[app]\neditable = true\n").await;
    for privacy in [Privacy::Readonly, Privacy::Private] {
        let id = create(&app.st, NewPaste { editable: true, ..with_password("v1", privacy, "pw") }).await;
        let ip = if privacy == Privacy::Readonly { IP } else { OTHER_IP };
        for _ in 0..5 {
            let res = paste::edit(&app.st, id, Access::Password("wrong".into()), ip, "v2".into(), None, NOW).await;
            assert!(matches!(res, Err(Error::Forbidden)), "{res:?}");
        }
        let res = paste::edit(&app.st, id, Access::Password("pw".into()), ip, "v2".into(), None, NOW).await;
        assert!(matches!(res, Err(Error::TooManyAttempts)), "{privacy:?}: {res:?}");
    }
}

#[tokio::test]
async fn wrong_delete_passwords_are_rate_limited() {
    let app = support::app().await;
    for (privacy, ip) in [(Privacy::Readonly, IP), (Privacy::Private, OTHER_IP)] {
        let id = create(&app.st, with_password("v1", privacy, "pw")).await;
        for _ in 0..5 {
            let res = paste::delete(&app.st, id, DeleteAuth::Password("wrong".into()), ip, NOW).await;
            assert!(matches!(res, Err(Error::Forbidden)), "{res:?}");
        }
        let res = paste::delete(&app.st, id, DeleteAuth::Password("pw".into()), ip, NOW).await;
        assert!(matches!(res, Err(Error::TooManyAttempts)), "{privacy:?}: {res:?}");
        paste::meta(&app.st, id, NOW).await.unwrap();
    }
}

#[tokio::test]
async fn wrong_secret_verifiers_are_rate_limited() {
    let app = support::app().await;
    let id = create(&app.st, secret_paste(PBKDF2_ITERATIONS)).await;
    let right = crypto::browser_verifier(SECRET_PASSWORD, &VERIFIER_SALT);
    for _ in 0..5 {
        let res = paste::delete(&app.st, id, DeleteAuth::Verifier([1; 32]), IP, NOW).await;
        assert!(matches!(res, Err(Error::Forbidden)), "{res:?}");
    }
    let res = paste::delete(&app.st, id, DeleteAuth::Verifier(right), IP, NOW).await;
    assert!(matches!(res, Err(Error::TooManyAttempts)), "{res:?}");
    paste::delete(&app.st, id, DeleteAuth::Verifier(right), OTHER_IP, NOW).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn parallel_wrong_passwords_cannot_outrun_the_limit() {
    let app = support::app().await;
    let id = create(&app.st, with_password("guarded", Privacy::Private, "right")).await;
    let start = Arc::new(tokio::sync::Barrier::new(25));
    let tasks: Vec<_> = (0..25)
        .map(|_| {
            let st = app.st.clone();
            let start = start.clone();
            tokio::spawn(async move {
                start.wait().await;
                paste::read(&st, id, Access::Password("wrong".into()), IP, NOW).await
            })
        })
        .collect();
    let mut checked = 0;
    for t in tasks {
        match t.await.unwrap() {
            Err(Error::WrongPassword) => checked += 1,
            Err(Error::TooManyAttempts) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(checked <= 5, "{checked} guesses were checked");
}

#[tokio::test]
async fn a_readonly_paste_is_readable_by_anyone_but_deletable_only_with_its_password() {
    let app = support::app().await;
    let id = create(&app.st, with_password("read me", Privacy::Readonly, "pw")).await;
    assert_eq!(text(&read(&app.st, id, Access::Anonymous).await.unwrap().body), "read me");
    assert!(paste::meta(&app.st, id, NOW).await.unwrap().password_hash.unwrap().starts_with("$argon2id$"));
    assert!(matches!(paste::delete(&app.st, id, DeleteAuth::None, IP, NOW).await, Err(Error::Forbidden)));
    assert!(matches!(
        paste::delete(&app.st, id, DeleteAuth::Password("wrong".into()), IP, NOW).await,
        Err(Error::Forbidden)
    ));
    paste::delete(&app.st, id, DeleteAuth::Password("pw".into()), IP, NOW).await.unwrap();
    assert!(matches!(read(&app.st, id, Access::Anonymous).await, Err(Error::NotFound)));
}

#[tokio::test]
async fn a_private_paste_is_deletable_only_with_its_password() {
    let app = support::app().await;
    let id = create(&app.st, with_password("mine", Privacy::Private, "pw")).await;
    assert!(matches!(paste::delete(&app.st, id, DeleteAuth::None, IP, NOW).await, Err(Error::Forbidden)));
    assert!(matches!(
        paste::delete(&app.st, id, DeleteAuth::Password("wrong".into()), IP, NOW).await,
        Err(Error::Forbidden)
    ));
    paste::delete(&app.st, id, DeleteAuth::Password("pw".into()), IP, NOW).await.unwrap();
    assert!(matches!(paste::meta(&app.st, id, NOW).await, Err(Error::NotFound)));
}

#[tokio::test]
async fn public_and_unlisted_pastes_can_be_deleted_by_anyone() {
    let app = support::app().await;
    for privacy in [Privacy::Public, Privacy::Unlisted] {
        let id = create(&app.st, new("bye", privacy)).await;
        paste::delete(&app.st, id, DeleteAuth::None, IP, NOW).await.unwrap();
        assert!(matches!(paste::meta(&app.st, id, NOW).await, Err(Error::NotFound)));
    }
}

#[tokio::test]
async fn deleting_removes_the_file_directory() {
    let app = support::app().await;
    let id = create(&app.st, new("bye", Privacy::Public)).await;
    let dir = app.st.files_dir.join(id.0.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("0"), b"x").unwrap();
    paste::delete(&app.st, id, DeleteAuth::None, IP, NOW).await.unwrap();
    assert!(!dir.exists());
}

#[tokio::test]
async fn the_admin_can_delete_any_paste() {
    let app = support::app().await;
    let private = create(&app.st, with_password("x", Privacy::Private, "pw")).await;
    let secret = create(&app.st, secret_paste(PBKDF2_ITERATIONS)).await;
    let readonly = create(&app.st, with_password("x", Privacy::Readonly, "pw")).await;
    for id in [private, secret, readonly] {
        paste::delete(&app.st, id, DeleteAuth::Admin, IP, NOW).await.unwrap();
        assert!(matches!(paste::meta(&app.st, id, NOW).await, Err(Error::NotFound)));
    }
}

#[tokio::test]
async fn a_secret_paste_returns_its_ciphertext_and_deletes_only_with_the_verifier() {
    let app = support::app().await;
    let parts = secret_paste(PBKDF2_ITERATIONS);
    let container = parts.secret.as_ref().unwrap().container.clone();
    let id = create(&app.st, parts).await;
    let opened = read(&app.st, id, Access::Anonymous).await.unwrap();
    assert!(matches!(&opened.body, Body::Cipher(c) if *c == container));
    assert_eq!(opened.paste.verifier_salt, Some(VERIFIER_SALT));
    assert!(matches!(paste::delete(&app.st, id, DeleteAuth::None, IP, NOW).await, Err(Error::Forbidden)));
    assert!(matches!(
        paste::delete(&app.st, id, DeleteAuth::Password(SECRET_PASSWORD.into()), IP, NOW).await,
        Err(Error::Forbidden)
    ));
    let wrong = crypto::browser_verifier("not it", &VERIFIER_SALT);
    assert!(matches!(paste::delete(&app.st, id, DeleteAuth::Verifier(wrong), IP, NOW).await, Err(Error::Forbidden)));
    let right = crypto::browser_verifier(SECRET_PASSWORD, &VERIFIER_SALT);
    paste::delete(&app.st, id, DeleteAuth::Verifier(right), IP, NOW).await.unwrap();
    assert!(matches!(paste::meta(&app.st, id, NOW).await, Err(Error::NotFound)));
}

#[tokio::test]
async fn a_secret_paste_stores_only_a_hash_of_its_verifier() {
    let app = support::app().await;
    let id = create(&app.st, secret_paste(PBKDF2_ITERATIONS)).await;
    let stored = paste::meta(&app.st, id, NOW).await.unwrap().verifier_hash.unwrap();
    let verifier = crypto::browser_verifier(SECRET_PASSWORD, &VERIFIER_SALT);
    assert_eq!(stored.len(), 48);
    assert_eq!(&stored[..16], &VERIFIER_SALT);
    assert_eq!(&stored[16..], &crypto::verifier_hash(&verifier));
}

#[tokio::test]
async fn secret_pastes_with_weak_parameters_are_refused() {
    let app = support::app().await;
    let weak = secret_paste(PBKDF2_ITERATIONS - 1);
    assert!(matches!(paste::create(&app.st, weak, None, NOW).await, Err(Error::UnsupportedFormat)));
    let server_container = NewPaste {
        secret: Some(SecretParts {
            container: crypto::seal(&crypto::Dek::random(), b"x"),
            verifier_salt: VERIFIER_SALT,
            verifier: [0; 32],
        }),
        ..new("", Privacy::Secret)
    };
    assert!(matches!(paste::create(&app.st, server_container, None, NOW).await, Err(Error::UnsupportedFormat)));
    assert_eq!(row_count(&app.st).await, 0);
}

#[tokio::test]
async fn burn_after_one_read_shows_the_paste_once() {
    let app = support::app().await;
    let id = create(&app.st, NewPaste { burn_after_reads: 1, ..new("once", Privacy::Unlisted) }).await;
    let first = read(&app.st, id, Access::Anonymous).await.unwrap();
    assert_eq!(text(&first.body), "once");
    let grant = first.grant.expect("the burning read carries a grant");
    assert_eq!(bitvault::domain::grant::check(&app.st.grant_key, &grant, id, NOW).unwrap(), None);
    assert!(matches!(read(&app.st, id, Access::Anonymous).await, Err(Error::NotFound)));
    assert!(matches!(paste::meta(&app.st, id, NOW).await, Err(Error::NotFound)));
    assert!(matches!(paste::delete(&app.st, id, DeleteAuth::None, IP, NOW).await, Err(Error::NotFound)));
}

#[tokio::test]
async fn the_burning_read_of_a_private_paste_carries_its_data_key() {
    let app = support::app().await;
    let id = create(&app.st, NewPaste { burn_after_reads: 1, ..with_password("once", Privacy::Private, "pw") }).await;
    let first = read(&app.st, id, Access::Password("pw".into())).await.unwrap();
    let grant = first.grant.unwrap();
    assert!(bitvault::domain::grant::check(&app.st.grant_key, &grant, id, NOW).unwrap().is_some());
    assert!(matches!(read(&app.st, id, Access::Grant(grant)).await, Err(Error::NotFound)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_reads_of_a_burn_after_one_paste_succeed_exactly_once() {
    let app = support::app().await;
    let id = create(&app.st, NewPaste { burn_after_reads: 1, ..new("race", Privacy::Public) }).await;
    let start = Arc::new(tokio::sync::Barrier::new(16));
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let st = app.st.clone();
            let start = start.clone();
            tokio::spawn(async move {
                start.wait().await;
                paste::read(&st, id, Access::Anonymous, IP, NOW).await
            })
        })
        .collect();
    let mut ok = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => ok += 1,
            Err(Error::NotFound) => {}
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }
    assert_eq!(ok, 1);
    let reads: i64 = sqlx::query_scalar("SELECT read_count FROM pastes WHERE id = ?")
        .bind(id.0 as i64)
        .fetch_one(&app.st.pool)
        .await
        .unwrap();
    assert_eq!(reads, 1);
}

#[tokio::test]
async fn burn_after_three_reads_counts_reads_not_metadata_views() {
    let app = support::app().await;
    let id = create(&app.st, NewPaste { burn_after_reads: 3, ..new("thrice", Privacy::Public) }).await;
    for _ in 0..5 {
        paste::meta(&app.st, id, NOW).await.unwrap();
    }
    for n in 1..=3u64 {
        let opened = read(&app.st, id, Access::Anonymous).await.unwrap();
        assert_eq!(opened.paste.read_count, n);
        assert_eq!(opened.grant.is_some(), n == 3);
    }
    assert!(matches!(read(&app.st, id, Access::Anonymous).await, Err(Error::NotFound)));
}

#[tokio::test]
async fn reads_record_the_count_and_the_last_read_time() {
    let app = support::app().await;
    let id = create(&app.st, new("counted", Privacy::Public)).await;
    paste::read(&app.st, id, Access::Anonymous, IP, NOW + 5).await.unwrap();
    let p = paste::meta(&app.st, id, NOW + 6).await.unwrap();
    assert_eq!(p.read_count, 1);
    assert_eq!(p.last_read_at, Some(NOW + 5));
    assert_eq!(p.burned_at, None);
}

#[tokio::test]
async fn an_expired_paste_is_gone_immediately() {
    let app = support::app().await;
    let id = create(&app.st, NewPaste { expiry: Expiry::Min1, ..new("brief", Privacy::Public) }).await;
    paste::read(&app.st, id, Access::Anonymous, IP, NOW + 59).await.unwrap();
    assert!(matches!(paste::read(&app.st, id, Access::Anonymous, IP, NOW + 61).await, Err(Error::NotFound)));
    assert!(matches!(paste::meta(&app.st, id, NOW + 61).await, Err(Error::NotFound)));
    assert!(paste::list_public(&app.st, 1, NOW + 61).await.unwrap().is_empty());
    assert!(paste::list_all(&app.st, NOW + 61).await.unwrap().is_empty());
}

#[tokio::test]
async fn purge_removes_expired_and_long_burned_rows() {
    let app = support::app().await;
    create(&app.st, NewPaste { expiry: Expiry::Min1, ..new("brief", Privacy::Public) }).await;
    let burned = create(&app.st, NewPaste { burn_after_reads: 1, ..new("once", Privacy::Public) }).await;
    read(&app.st, burned, Access::Anonymous).await.unwrap();
    let dir = app.st.files_dir.join(burned.0.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    assert_eq!(paste::purge(&app.st, NOW + 61).await.unwrap(), 1);
    assert_eq!(row_count(&app.st).await, 1);
    assert!(dir.exists());
    assert_eq!(paste::purge(&app.st, NOW + 601).await.unwrap(), 1);
    assert_eq!(row_count(&app.st).await, 0);
    assert!(!dir.exists());
}

#[tokio::test]
async fn purge_keeps_live_pastes() {
    let app = support::app().await;
    create(&app.st, NewPaste { expiry: Expiry::Week1, ..new("stays", Privacy::Public) }).await;
    assert_eq!(paste::purge(&app.st, NOW + 86_400).await.unwrap(), 0);
    assert_eq!(row_count(&app.st).await, 1);
}

#[tokio::test]
async fn expiry_beyond_the_maximum_is_refused() {
    let app = support::app().await;
    let res = paste::create(&app.st, NewPaste { expiry: Expiry::Month1, ..new("x", Privacy::Public) }, None, NOW).await;
    match res {
        Err(Error::Invalid(msg)) => assert!(msg.contains("1 week"), "{msg}"),
        other => panic!("expected Invalid, got {other:?}"),
    }
    let res = paste::create(&app.st, NewPaste { expiry: Expiry::Never, ..new("x", Privacy::Public) }, None, NOW).await;
    assert!(matches!(res, Err(Error::Invalid(_))));
}

#[tokio::test]
async fn never_expiring_pastes_are_allowed_when_configured() {
    let app = support::app_with("[app]\nmax_expiry = \"never\"\n").await;
    let id = create(&app.st, NewPaste { expiry: Expiry::Never, ..new("forever", Privacy::Public) }).await;
    assert_eq!(paste::meta(&app.st, id, NOW).await.unwrap().expires_at, None);
}

#[tokio::test]
async fn expiry_and_privacy_outside_the_offered_choices_are_refused() {
    let app = support::app_with(
        "[app]\nexpiry_choices = [\"10min\", \"1hour\"]\ndefault_expiry = \"1hour\"\nmax_expiry = \"1hour\"\n\
         privacy_levels = [\"public\"]\ndefault_privacy = \"public\"\n",
    )
    .await;
    let res = paste::create(&app.st, NewPaste { expiry: Expiry::Min1, ..new("x", Privacy::Public) }, None, NOW).await;
    assert!(matches!(res, Err(Error::Invalid(_))));
    let res =
        paste::create(&app.st, NewPaste { expiry: Expiry::Hour1, ..new("x", Privacy::Unlisted) }, None, NOW).await;
    assert!(matches!(res, Err(Error::Invalid(_))));
    create(&app.st, NewPaste { expiry: Expiry::Hour1, ..new("x", Privacy::Public) }).await;
}

#[tokio::test]
async fn password_levels_need_a_password_and_secret_needs_its_container() {
    let app = support::app().await;
    for privacy in [Privacy::Readonly, Privacy::Private] {
        assert!(matches!(paste::create(&app.st, new("x", privacy), None, NOW).await, Err(Error::Invalid(_))));
        let empty = with_password("x", privacy, "");
        assert!(matches!(paste::create(&app.st, empty, None, NOW).await, Err(Error::Invalid(_))));
    }
    assert!(matches!(paste::create(&app.st, new("x", Privacy::Secret), None, NOW).await, Err(Error::Invalid(_))));
    assert!(matches!(paste::create(&app.st, new("  \n", Privacy::Public), None, NOW).await, Err(Error::Invalid(_))));
}

#[test]
fn expiry_choices_parse_and_measure_their_length() {
    let all = [
        ("1min", Some(60)),
        ("10min", Some(600)),
        ("1hour", Some(3_600)),
        ("24hour", Some(86_400)),
        ("3days", Some(259_200)),
        ("1week", Some(604_800)),
        ("1month", Some(2_592_000)),
        ("6months", Some(15_552_000)),
        ("1year", Some(31_536_000)),
        ("never", None),
    ];
    for (name, secs) in all {
        let e = Expiry::parse(name).unwrap();
        assert_eq!(e.as_str(), name);
        assert_eq!(e.seconds(), secs);
    }
    assert_eq!(Expiry::parse("2min"), None);
}

#[tokio::test]
async fn editing_is_refused_unless_enabled_in_config_and_on_the_paste() {
    let off = support::app().await;
    let id = create(&off.st, NewPaste { editable: true, ..new("v1", Privacy::Public) }).await;
    let res = paste::edit(&off.st, id, Access::Anonymous, IP, "v2".into(), None, NOW).await;
    assert!(matches!(res, Err(Error::Forbidden)));

    let on = support::app_with("[app]\neditable = true\n").await;
    let fixed = create(&on.st, new("v1", Privacy::Public)).await;
    let res = paste::edit(&on.st, fixed, Access::Anonymous, IP, "v2".into(), None, NOW).await;
    assert!(matches!(res, Err(Error::Forbidden)));

    let id = create(&on.st, NewPaste { editable: true, ..new("v1", Privacy::Public) }).await;
    paste::edit(&on.st, id, Access::Anonymous, IP, "v2".into(), Some("rust".into()), NOW).await.unwrap();
    let opened = read(&on.st, id, Access::Anonymous).await.unwrap();
    assert_eq!(text(&opened.body), "v2");
    assert_eq!(opened.paste.syntax.as_deref(), Some("rust"));
}

#[tokio::test]
async fn editing_a_readonly_or_private_paste_needs_its_password() {
    let app = support::app_with("[app]\neditable = true\n").await;
    for privacy in [Privacy::Readonly, Privacy::Private] {
        let id = create(&app.st, NewPaste { editable: true, ..with_password("v1", privacy, "pw") }).await;
        let res = paste::edit(&app.st, id, Access::Anonymous, IP, "v2".into(), None, NOW).await;
        assert!(matches!(res, Err(Error::Forbidden)));
        let res = paste::edit(&app.st, id, Access::Password("wrong".into()), IP, "v2".into(), None, NOW).await;
        assert!(matches!(res, Err(Error::Forbidden)));
        paste::edit(&app.st, id, Access::Password("pw".into()), IP, "v2".into(), None, NOW).await.unwrap();
        let access = if privacy == Privacy::Private { Access::Password("pw".into()) } else { Access::Anonymous };
        let opened = paste::read(&app.st, id, access, OTHER_IP, NOW).await.unwrap();
        assert_eq!(text(&opened.body), "v2");
        if privacy == Privacy::Private {
            assert!(!stored_content(&app.st, id).await.windows(2).any(|w| w == b"v2"));
        }
    }
}

#[tokio::test]
async fn editing_a_public_paste_into_a_url_makes_it_a_redirect() {
    let app = support::app_with("[app]\neditable = true\n").await;
    let id = create(&app.st, NewPaste { editable: true, ..new("v1", Privacy::Public) }).await;
    paste::edit(&app.st, id, Access::Anonymous, IP, "https://example.org".into(), None, NOW).await.unwrap();
    assert_eq!(paste::meta(&app.st, id, NOW).await.unwrap().kind, Kind::Url);
}

#[tokio::test]
async fn secret_pastes_are_never_editable() {
    let app = support::app_with("[app]\neditable = true\n").await;
    let id = create(&app.st, NewPaste { editable: true, ..secret_paste(PBKDF2_ITERATIONS) }).await;
    let res = paste::edit(&app.st, id, Access::Anonymous, IP, "x".into(), None, NOW).await;
    assert!(matches!(res, Err(Error::Forbidden)));
}

#[tokio::test]
async fn id_collisions_retry() {
    let app = support::app().await;
    let taken = create(&app.st, new("first", Privacy::Public)).await;
    let free = taken.0 ^ 1;
    paste::set_id_source(vec![taken.0, free]);
    let id = create(&app.st, new("second", Privacy::Public)).await;
    assert_eq!(id, PasteId(free));
    assert_eq!(text(&read(&app.st, taken, Access::Anonymous).await.unwrap().body), "first");
}

#[tokio::test]
async fn eight_collisions_exhaust_the_id_space() {
    let app = support::app().await;
    let taken = create(&app.st, new("first", Privacy::Public)).await;
    paste::set_id_source(vec![taken.0; 8]);
    let res = paste::create(&app.st, new("second", Privacy::Public), None, NOW).await;
    assert!(matches!(res, Err(Error::IdSpaceExhausted)));
}

#[tokio::test]
async fn the_admin_list_holds_every_live_paste_but_no_burned_ones() {
    let app = support::app().await;
    let a = create(&app.st, with_password("x", Privacy::Private, "pw")).await;
    let b = create(&app.st, new("y", Privacy::Unlisted)).await;
    let burned = create(&app.st, NewPaste { burn_after_reads: 1, ..new("z", Privacy::Public) }).await;
    read(&app.st, burned, Access::Anonymous).await.unwrap();
    let mut ids: Vec<u64> = paste::list_all(&app.st, NOW).await.unwrap().iter().map(|p| p.id.0).collect();
    ids.sort_unstable();
    let mut want = vec![a.0, b.0];
    want.sort_unstable();
    assert_eq!(ids, want);
}

#[tokio::test]
async fn a_paste_debug_print_hides_its_content_and_secrets() {
    let app = support::app().await;
    let id = create(&app.st, with_password("very secret words", Privacy::Readonly, "pw")).await;
    let printed = format!("{:?}", paste::meta(&app.st, id, NOW).await.unwrap());
    assert!(!printed.contains("very secret words"));
    assert!(!printed.contains("argon2id"));
}
