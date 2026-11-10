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
fn runs_of_spaces_and_hyphens_count_as_one_separator() {
    let full = words::parse("happy-apple-banana").unwrap();
    assert_eq!(words::parse("happy   apple \t banana").unwrap(), full);
    assert_eq!(words::parse("--happy -- apple- -banana-").unwrap(), full);
}

#[test]
fn words_typed_without_separators_are_read_when_only_one_reading_fits() {
    let full = words::parse("happy-apple-banana").unwrap();
    assert_eq!(words::parse("happyapplebanana").unwrap(), full);
    assert_eq!(words::parse("HappyAppleBanana").unwrap(), full);
    assert_eq!(words::parse("happy applebanana").unwrap(), full);
    assert_eq!(words::parse("happyapple-banana").unwrap(), full);
    // A part on its own may still be a prefix.
    assert_eq!(words::parse("happ applebanana").unwrap(), full);
    assert_eq!(words::parse("actaddzoo").unwrap(), words::parse("act-add-zoo").unwrap());
}

#[test]
fn joined_words_round_trip_unless_they_read_two_ways() {
    let mut ambiguous = 0;
    for _ in 0..10_000 {
        let id = PasteId::random();
        match words::parse(&id.words().replace('-', "")) {
            Ok(found) => assert_eq!(found, id),
            Err(Error::Invalid(m)) if m.contains("more than one") => ambiguous += 1,
            other => panic!("{} gave {other:?}", id.words()),
        }
    }
    // About 1 in 20,000 triples reads two ways.
    assert!(ambiguous < 10, "{ambiguous}");
}

#[test]
fn joined_words_that_read_two_ways_ask_for_separators() {
    // "quality sea then" or "quality seat hen".
    match words::parse("qualityseathen") {
        Err(Error::Invalid(m)) => assert!(m.contains("Put spaces or hyphens between the words"), "{m}"),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(words::parse("quality seat hen").unwrap(), words::parse("quality-seat-hen").unwrap());
}

#[test]
fn joined_letters_that_are_not_three_words_are_rejected() {
    for input in ["happyapple", "happyapplebananaable", "happyaplebanana", "xyzxyzxyz", "happy"] {
        assert!(matches!(words::parse(input), Err(Error::Invalid(_))), "{input}");
    }
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

#[test]
fn an_unambiguous_prefix_of_four_letters_or_more_stands_for_its_word() {
    let full = words::parse("happy-apple-banana").unwrap();
    assert_eq!(words::parse("happ appl bana").unwrap(), full);
    assert_eq!(words::parse("HAPPY appl-banan").unwrap(), full);
}

#[test]
fn every_word_is_found_from_its_first_four_letters() {
    for (i, word) in words::list().iter().enumerate() {
        let prefix: String = word.chars().take(4).collect();
        let id = words::parse(&format!("{prefix} abandon abandon")).unwrap();
        assert_eq!(id.0 >> 22, i as u64, "{prefix} must stand for {word}");
    }
}

#[test]
fn a_word_shorter_than_four_letters_must_be_typed_in_full() {
    assert_eq!(words::parse("act add zoo").unwrap(), words::parse("act-add-zoo").unwrap());
    match words::parse("hap apple banana") {
        Err(Error::Invalid(m)) => assert_eq!(m, "\"hap\" is too short. Type at least four letters of each word."),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn a_prefix_that_fits_several_words_is_named_in_the_error() {
    let list = ["happen", "happy", "harbor"];
    match words::find_in(&list, "happ") {
        Err(Error::Invalid(m)) => assert_eq!(m, "\"happ\" fits more than one paste word. Type more letters."),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(words::find_in(&list, "happy").unwrap(), 1);
    assert_eq!(words::find_in(&list, "harb").unwrap(), 2);
}

#[test]
fn the_browser_word_list_matches_the_server_list() {
    let asset = bitvault::assets::Assets::get("bip39-english.txt").expect("the word list asset");
    let text = std::str::from_utf8(&asset.data).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines, words::list());
    assert!(text.ends_with('\n') && !text.ends_with("\n\n"));
}
