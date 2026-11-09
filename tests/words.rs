#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use bitvault::domain::words::{self, PasteId};
use bitvault::domain::{Kind, Privacy};
use bitvault::error::Error;

#[test]
fn every_id_round_trips_through_its_words() {
    for _ in 0..10_000 {
        let id = PasteId::random();
        assert!(id.0 < 1 << words::ID_BITS);
        assert_eq!(words::parse(&id.words()).unwrap(), id);
    }
}

#[test]
fn the_first_and_last_ids_map_to_the_first_and_last_words() {
    assert_eq!(PasteId(0).words(), "abandon-abandon-abandon");
    assert_eq!(PasteId((1 << 33) - 1).words(), "zoo-zoo-zoo");
    assert_eq!(words::parse("zoo-zoo-zoo").unwrap(), PasteId((1 << 33) - 1));
}

#[test]
fn input_with_spaces_mixed_case_and_hyphens_is_accepted() {
    assert_eq!(words::parse(" Happy  apple-BANANA ").unwrap(), words::parse("happy-apple-banana").unwrap());
}

#[test]
fn an_unknown_word_is_named_in_the_error() {
    match words::parse("happy-aple-banana") {
        Err(Error::Invalid(m)) => assert_eq!(m, "\"aple\" is not one of the paste words. Check the spelling."),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn two_or_four_words_are_rejected() {
    assert!(matches!(words::parse("happy-apple"), Err(Error::Invalid(_))));
    assert!(matches!(words::parse("happy-apple-banana-able"), Err(Error::Invalid(_))));
}

#[test]
fn the_word_list_is_sorted_so_binary_search_is_valid() {
    assert!(words::word_list_is_sorted());
}

#[test]
fn privacy_and_kind_round_trip_and_report_their_rules() {
    for p in [Privacy::Public, Privacy::Unlisted, Privacy::Readonly, Privacy::Private, Privacy::Secret] {
        assert_eq!(Privacy::parse(p.as_str()), Some(p));
    }
    assert_eq!(Privacy::parse("nope"), None);
    assert!(Privacy::Public.listed() && !Privacy::Unlisted.listed());
    assert!(!Privacy::Public.needs_password() && !Privacy::Unlisted.needs_password());
    assert!(
        Privacy::Readonly.needs_password() && Privacy::Private.needs_password() && Privacy::Secret.needs_password()
    );
    assert_eq!(Kind::parse("url"), Some(Kind::Url));
    assert_eq!(Kind::parse(Kind::Text.as_str()), Some(Kind::Text));
    assert_eq!(Kind::parse("x"), None);
}

#[tokio::test]
async fn the_migration_creates_both_tables() {
    let dir = tempfile::tempdir().unwrap();
    let pool = bitvault::db::open(&dir.path().join("data")).await.unwrap();
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(names.contains(&"pastes".to_string()));
    assert!(names.contains(&"paste_files".to_string()));
}
