#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitvault::domain::crypto;
use bitvault::domain::expiry::Expiry;
use bitvault::domain::files::Staging;
use bitvault::domain::live::ot::{Op, Part};
use bitvault::domain::live::room::{
    self, ClientId, EditorEvent, Init, Joined, Msg, Peer, Rooms, StreamGuard, Timing, WatchEvent,
};
use bitvault::domain::paste::{self, Access, NewPaste, Paste, TEXT_LIMIT};
use bitvault::domain::{self, Privacy};
use bitvault::error::Error;
use bitvault::state::AppState;
use bytes::Bytes;
use futures_util::stream;
use support::App;
use tokio::sync::broadcast::Receiver;

const PASSWORD: &str = "live-pw-123";
const CONFIG: &str = "[app]\neditable = true\n";
/// How long any awaited event or state may take before a test fails.
const PATIENCE: Duration = Duration::from_secs(10);

fn ip(n: u32) -> IpAddr {
    let [_, a, b, c] = n.to_be_bytes();
    IpAddr::V4(Ipv4Addr::new(10, a, b, c))
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn timing() -> Timing {
    Timing {
        idle_save: ms(50),
        max_unsaved: ms(300),
        session_grace: ms(300),
        presence_grace: ms(100),
        render_every: ms(100),
        peers_every: ms(20),
    }
}

async fn live_app() -> App {
    support::app_with_timing(CONFIG, timing()).await
}

async fn create_with(st: &AppState, content: &str, privacy: Privacy, staging: Option<Staging>) -> Paste {
    let new = NewPaste {
        content: content.into(),
        privacy,
        expiry: Expiry::Hour24,
        burn_after_reads: 0,
        syntax: None,
        editable: true,
        password: (privacy == Privacy::Private).then(|| PASSWORD.to_owned()),
        secret: None,
    };
    let id = paste::create(st, new, staging, domain::now()).await.unwrap();
    paste::meta(st, id, domain::now()).await.unwrap()
}

async fn create(st: &AppState, content: &str, privacy: Privacy) -> Paste {
    create_with(st, content, privacy, None).await
}

async fn dek(p: &Paste) -> crypto::Dek {
    crypto::unwrap_dek(PASSWORD, p.wrapped_key.as_deref().unwrap()).await.unwrap()
}

struct Editor {
    init: Init,
    peer: u32,
    events: Receiver<EditorEvent>,
    _guard: StreamGuard,
}

async fn join_with(st: &AppState, p: &Paste, ip: IpAddr, dek: Option<crypto::Dek>) -> Editor {
    match room::join(st, p, dek, ip, None).await.unwrap() {
        Joined::In { init: Some(init), replay, events, guard, peer } => {
            assert!(replay.is_empty());
            assert_eq!(peer, init.peer);
            Editor { init, peer, events, _guard: guard }
        }
        Joined::In { init: None, .. } => panic!("a fresh join got no init"),
        Joined::Full => panic!("the room is full"),
    }
}

async fn join(st: &AppState, p: &Paste, ip: IpAddr) -> Editor {
    join_with(st, p, ip, None).await
}

fn insert(len: u32, at: u32, s: &str) -> Op {
    Op::from_parts([Part::Keep(at), Part::Insert(s.into()), Part::Keep(len - at)])
}

fn edit(seq: u64, base: u64, op: Op) -> Msg {
    Msg::Edit { seq, base, op, pos: 0 }
}

/// The next `op` event, skipping the others.
async fn next_op(rx: &mut Receiver<EditorEvent>) -> (u64, u32, u64, Op) {
    tokio::time::timeout(PATIENCE, async {
        loop {
            if let EditorEvent::Op { rev, peer, seq, op } = rx.recv().await.unwrap() {
                return (rev, peer, seq, op);
            }
        }
    })
    .await
    .expect("no op event arrived")
}

/// The next watcher event that `pick` accepts, skipping the others.
async fn next_watch<T>(rx: &mut Receiver<WatchEvent>, pick: impl Fn(WatchEvent) -> Option<T>) -> T {
    tokio::time::timeout(PATIENCE, async {
        loop {
            if let Some(t) = pick(rx.recv().await.unwrap()) {
                return t;
            }
        }
    })
    .await
    .expect("the expected watcher event did not arrive")
}

/// The stored kind and content bytes, straight from the table.
async fn row(st: &AppState, p: &Paste) -> (String, Vec<u8>) {
    sqlx::query_as("SELECT kind, content FROM pastes WHERE id = ?")
        .bind(p.id.0 as i64)
        .fetch_one(&st.pool)
        .await
        .unwrap()
}

async fn row_text(st: &AppState, p: &Paste) -> String {
    String::from_utf8(row(st, p).await.1).unwrap()
}

/// Polls `check` until it holds, failing after [`PATIENCE`].
async fn eventually<F: Future<Output = bool>>(what: &str, mut check: impl FnMut() -> F) {
    let start = Instant::now();
    while !check().await {
        assert!(start.elapsed() < PATIENCE, "never happened: {what}");
        tokio::time::sleep(ms(10)).await;
    }
}

async fn sessions_end(st: &AppState) {
    let rooms = Arc::clone(&st.rooms);
    eventually("every session ended", || {
        let rooms = Arc::clone(&rooms);
        async move { rooms.sessions() == 0 }
    })
    .await;
}

#[tokio::test]
async fn live_needs_every_condition() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    assert!(paste::live(st, &p));
    let private = create(st, "hello", Privacy::Private).await;
    assert!(paste::live(st, &private));

    let with_cfg = |toml_edit: fn(&mut bitvault::config::AppConfig)| {
        let mut cfg = (*st.cfg).clone();
        toml_edit(&mut cfg.app);
        AppState { cfg: Arc::new(cfg), ..st.clone() }
    };
    assert!(!paste::live(&with_cfg(|a| a.editable = false), &p), "editing switched off");
    assert!(!paste::live(&with_cfg(|a| a.live_edit = false), &p), "live edit switched off");
    assert!(!paste::live(st, &Paste { editable: false, ..p.clone() }), "the paste is not editable");
    assert!(!paste::live(st, &Paste { privacy: Privacy::Readonly, ..p.clone() }), "read-only");
    assert!(!paste::live(st, &Paste { privacy: Privacy::Secret, ..p.clone() }), "secret");
    assert!(!paste::live(st, &Paste { burn_after_reads: 1, ..p.clone() }), "burns after a read");
    assert!(!paste::live(st, &Paste { burned_at: Some(domain::now()), ..p.clone() }), "burned");
}

#[tokio::test]
async fn two_editors_converge_and_the_row_is_saved() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let mut a = join(st, &p, ip(1)).await;
    let mut b = join(st, &p, ip(2)).await;
    assert_eq!((a.init.rev, a.init.text.as_str()), (0, "hello"));
    assert_ne!(a.peer, b.peer);
    room::submit(st, &p, &a.init.client, edit(1, 0, insert(5, 0, "x"))).await.unwrap();
    room::submit(st, &p, &b.init.client, edit(1, 0, insert(5, 0, "y"))).await.unwrap();
    for rx in [&mut a.events, &mut b.events] {
        let first = next_op(rx).await;
        let second = next_op(rx).await;
        assert_eq!((first.0, first.1, first.2), (1, a.peer, 1));
        assert_eq!((second.0, second.1, second.2), (2, b.peer, 1));
        let text = second.3.apply(&first.3.apply("hello").unwrap()).unwrap();
        assert_eq!(text, "xyhello");
    }
    eventually("the row is saved", || async { row_text(st, &p).await == "xyhello" }).await;
    assert_eq!(paste::meta(st, p.id, domain::now()).await.unwrap().read_count, p.read_count);
}

#[tokio::test]
async fn a_retried_seq_applies_once() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let mut a = join(st, &p, ip(1)).await;
    room::submit(st, &p, &a.init.client, edit(1, 0, insert(5, 0, "x"))).await.unwrap();
    room::submit(st, &p, &a.init.client, edit(1, 0, insert(5, 0, "x"))).await.unwrap();
    room::submit(st, &p, &a.init.client, edit(2, 1, insert(6, 0, "z"))).await.unwrap();
    assert_eq!(next_op(&mut a.events).await.0, 1);
    let (rev, _, seq, _) = next_op(&mut a.events).await;
    assert_eq!((rev, seq), (2, 2), "the retry made no revision of its own");
}

#[tokio::test]
async fn crlf_becomes_lf() {
    let app = live_app().await;
    let p = create(&app.st, "a\r\nb\rc", Privacy::Unlisted).await;
    assert_eq!(join(&app.st, &p, ip(1)).await.init.text, "a\nb\nc");
}

#[tokio::test]
async fn an_edit_with_a_carriage_return_is_refused() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let a = join(st, &p, ip(1)).await;
    let refused = room::submit(st, &p, &a.init.client, edit(1, 0, insert(5, 0, "\r\n"))).await;
    assert!(matches!(refused, Err(Error::Invalid(_))), "{refused:?}");
}

#[tokio::test]
async fn continuous_typing_is_saved_by_max_unsaved() {
    let timing = Timing { idle_save: ms(500), max_unsaved: ms(1000), ..timing() };
    let app = support::app_with_timing(CONFIG, timing).await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let a = join(st, &p, ip(1)).await;
    let start = Instant::now();
    let mut len = 5;
    let mut seq = 0;
    loop {
        seq += 1;
        room::submit(st, &p, &a.init.client, edit(seq, seq - 1, insert(len, len, "."))).await.unwrap();
        len += 1;
        if row_text(st, &p).await != "hello" {
            break;
        }
        assert!(start.elapsed() < PATIENCE, "continuous typing was never saved");
        tokio::time::sleep(timing.idle_save / 2).await;
    }
    // Typing never paused for `idle_save`, so only `max_unsaved` can have saved it.
    assert!(start.elapsed() >= timing.max_unsaved, "saved after {:?}", start.elapsed());
    assert!(start.elapsed() < timing.max_unsaved + ms(2000), "saved only after {:?}", start.elapsed());
}

#[tokio::test]
async fn empty_text_is_not_saved() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let a = join(st, &p, ip(1)).await;
    room::submit(st, &p, &a.init.client, edit(1, 0, Op::from_parts([Part::Delete(5)]))).await.unwrap();
    drop(a);
    sessions_end(st).await;
    assert_eq!(row_text(st, &p).await, "hello");

    let mut staging = Staging::new(&st.files_dir).unwrap();
    let body = stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"bytes"))]);
    staging.add("a.txt", "", body, u64::MAX).await.unwrap();
    let with_file = create_with(st, "hello", Privacy::Unlisted, Some(staging)).await;
    let a = join(st, &with_file, ip(1)).await;
    room::submit(st, &with_file, &a.init.client, edit(1, 0, Op::from_parts([Part::Delete(5)]))).await.unwrap();
    eventually("the empty text is saved", || async { row_text(st, &with_file).await.is_empty() }).await;
}

#[tokio::test]
async fn a_url_makes_a_url_paste_and_watchers_reload() {
    let app = live_app().await;
    let st = &app.st;
    let url = "https://example.org/";
    let p = create(st, "hello", Privacy::Unlisted).await;
    let mut watcher = room::watch(st, &p, ip(9)).unwrap();
    let a = join(st, &p, ip(1)).await;
    room::submit(st, &p, &a.init.client, edit(1, 0, Op::from_texts("hello", url))).await.unwrap();
    eventually("the row becomes a URL paste", || async { row(st, &p).await == ("url".into(), url.into()) }).await;
    next_watch(&mut watcher.events, |e| matches!(e, WatchEvent::Reload).then_some(())).await;

    let private = create(st, "hello", Privacy::Private).await;
    let before = row(st, &private).await.1;
    let a = join_with(st, &private, ip(1), Some(dek(&private).await)).await;
    room::submit(st, &private, &a.init.client, edit(1, 0, Op::from_texts("hello", url))).await.unwrap();
    eventually("the private row is saved", || async { row(st, &private).await.1 != before }).await;
    assert_eq!(row(st, &private).await.0, "text");
}

#[tokio::test]
async fn private_text_is_sealed_with_the_session_key() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Private).await;
    let before = row(st, &p).await.1;
    let a = join_with(st, &p, ip(1), Some(dek(&p).await)).await;
    assert_eq!(a.init.text, "hello");
    room::submit(st, &p, &a.init.client, edit(1, 0, insert(5, 5, " world"))).await.unwrap();
    eventually("the private row is saved", || async { row(st, &p).await.1 != before }).await;
    assert!(!row(st, &p).await.1.windows(5).any(|w| w == b"world"), "the row holds plaintext");
    let found = paste::meta(st, p.id, domain::now()).await.unwrap();
    let opened = paste::read(st, &found, Access::Password(PASSWORD.into()), ip(1), domain::now()).await.unwrap();
    assert!(matches!(opened.body, paste::Body::Text(t) if t == "hello world"));
}

#[tokio::test]
async fn a_private_session_needs_its_key() {
    let app = live_app().await;
    let p = create(&app.st, "hello", Privacy::Private).await;
    let refused = room::join(&app.st, &p, None, ip(1), None).await;
    assert!(matches!(refused, Err(Error::Forbidden)));
}

/// Joins A and B, closes A's stream and lets B make three edits.
async fn three_edits_while_away(st: &AppState, p: &Paste) -> (ClientId, u32, Editor) {
    let a = join(st, p, ip(1)).await;
    let b = join(st, p, ip(2)).await;
    let (client, peer) = (a.init.client.clone(), a.peer);
    drop(a);
    for seq in 1..=3 {
        let len = 4 + u32::try_from(seq).unwrap();
        room::submit(st, p, &b.init.client, edit(seq, seq - 1, insert(len, len, "!"))).await.unwrap();
    }
    (client, peer, b)
}

#[tokio::test]
async fn resume_replays() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let (client, peer, b) = three_edits_while_away(st, &p).await;
    let Joined::In { init, replay, peer: again, .. } =
        room::join(st, &p, None, ip(1), Some((client, 0))).await.unwrap()
    else {
        panic!("full")
    };
    assert!(init.is_none());
    assert_eq!(again, peer);
    let [ops @ .., syntax, peers] = replay.as_slice() else { panic!("replayed too little: {replay:?}") };
    let revs: Vec<u64> = ops
        .iter()
        .map(|e| match e {
            EditorEvent::Op { rev, .. } => *rev,
            other => panic!("replayed {other:?}"),
        })
        .collect();
    assert_eq!(revs, [1, 2, 3]);
    assert!(matches!(syntax, EditorEvent::Syntax(None)), "{syntax:?}");
    let EditorEvent::Peers(peers) = peers else { panic!("the replay ends without peers: {peers:?}") };
    let mut present: Vec<u32> = peers.iter().map(|p| p.peer).collect();
    present.sort_unstable();
    let mut want = vec![peer, b.peer];
    want.sort_unstable();
    assert_eq!(present, want, "the resumed client sees who is here");
}

#[tokio::test]
async fn resume_brings_a_syntax_change() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let a = join(st, &p, ip(1)).await;
    let b = join(st, &p, ip(2)).await;
    let (client, rev) = (a.init.client.clone(), a.init.rev);
    drop(a);
    room::submit(st, &p, &b.init.client, Msg::Syntax(Some("rust".into()))).await.unwrap();
    let Joined::In { init, replay, .. } = room::join(st, &p, None, ip(1), Some((client, rev))).await.unwrap() else {
        panic!("full")
    };
    assert!(init.is_none());
    let syntax = replay.iter().rev().find_map(|e| match e {
        EditorEvent::Syntax(s) => Some(s.clone()),
        _ => None,
    });
    assert_eq!(syntax, Some(Some("rust".to_owned())), "{replay:?}");
}

#[tokio::test]
async fn resume_past_the_history_gets_init() {
    let app = support::app_with_rooms(CONFIG, Rooms::with_history(timing(), 2, 1 << 20)).await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let (client, _, _b) = three_edits_while_away(st, &p).await;
    let Joined::In { init, replay, .. } = room::join(st, &p, None, ip(1), Some((client, 0))).await.unwrap() else {
        panic!("full")
    };
    let init = init.expect("a client too far behind gets a fresh init");
    assert!(replay.is_empty());
    assert_eq!((init.rev, init.text.as_str()), (3, "hello!!!"));
}

#[tokio::test]
async fn session_ends_after_grace_and_saves() {
    let timing = Timing { idle_save: Duration::from_secs(600), max_unsaved: Duration::from_secs(600), ..timing() };
    let app = support::app_with_timing(CONFIG, timing).await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let a = join(st, &p, ip(1)).await;
    room::submit(st, &p, &a.init.client, edit(1, 0, insert(5, 5, "!"))).await.unwrap();
    let closed = Instant::now();
    drop(a);
    sessions_end(st).await;
    assert!(closed.elapsed() >= timing.session_grace);
    assert_eq!(row_text(st, &p).await, "hello!");
    let again = join(st, &p, ip(1)).await;
    assert_eq!((again.init.rev, again.init.text.as_str()), (0, "hello!"));
}

#[tokio::test]
async fn limits() {
    let app = live_app().await;
    let st = &app.st;

    let p = create(st, "hello", Privacy::Unlisted).await;
    let mut editors = Vec::new();
    for n in 0..64 {
        editors.push(join(st, &p, ip(n)).await);
    }
    assert!(matches!(room::join(st, &p, None, ip(64), None).await, Ok(Joined::Full)));
    drop(editors);

    let q = create(st, "hello", Privacy::Unlisted).await;
    let watchers: Vec<_> = (0..16).map(|_| room::watch(st, &q, ip(1000)).unwrap()).collect();
    assert!(matches!(room::watch(st, &q, ip(1000)), Err(Error::TooManyAttempts)));
    assert!(matches!(room::join(st, &q, None, ip(1000), None).await, Err(Error::TooManyAttempts)));
    drop(watchers);
    let watchers: Vec<_> = (0..256).map(|n| room::watch(st, &q, ip(2000 + n)).unwrap()).collect();
    assert!(matches!(room::watch(st, &q, ip(3000)), Err(Error::TooManyAttempts)));
    drop(watchers);

    let big = create(st, &"a".repeat(TEXT_LIMIT), Privacy::Unlisted).await;
    let a = join(st, &big, ip(1)).await;
    let len = u32::try_from(TEXT_LIMIT).unwrap();
    let refused = room::submit(st, &big, &a.init.client, edit(1, 0, insert(len, 0, "b"))).await;
    assert!(matches!(refused, Err(Error::TooLarge)), "{refused:?}");
    let b = join(st, &big, ip(2)).await;
    assert_eq!((b.init.rev, b.init.text.len()), (0, TEXT_LIMIT));

    drop((a, b));

    // Sessions count across pastes; each editor comes from its own address.
    let app = live_app().await;
    let st = &app.st;
    let mut editors = Vec::new();
    for n in 0..512 {
        let p = create(st, "hello", Privacy::Unlisted).await;
        editors.push(join(st, &p, ip(n)).await);
    }
    let p = create(st, "hello", Privacy::Unlisted).await;
    assert!(matches!(room::join(st, &p, None, ip(512), None).await, Err(Error::TooManyAttempts)));
}

#[tokio::test]
async fn edits_are_limited_per_editor() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let a = join(st, &p, ip(1)).await;
    let mut refused = 0;
    let mut rev = 0;
    for seq in 1..=60 {
        let len = 5 + u32::try_from(rev).unwrap();
        match room::submit(st, &p, &a.init.client, edit(seq, rev, insert(len, 0, "x"))).await {
            Ok(()) => rev += 1,
            Err(Error::TooManyAttempts) => refused += 1,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(refused > 0, "60 edits at once all passed");
    assert!(rev >= 30, "only {rev} edits passed");
}

#[tokio::test]
async fn watchers_hear_editors_and_content() {
    // The session outlives the test, so only the presence grace can bring the count to 0.
    let timing = Timing { session_grace: Duration::from_secs(600), ..timing() };
    let app = support::app_with_timing(CONFIG, timing).await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let mut watcher = room::watch(st, &p, ip(9)).unwrap();
    assert_eq!(watcher.editors, 0);
    let a = join(st, &p, ip(1)).await;
    let live = |e| match e {
        WatchEvent::Live { editors } => Some(editors),
        _ => None,
    };
    assert_eq!(next_watch(&mut watcher.events, live).await, 1);

    let start = Instant::now();
    let mut len = 5;
    let mut seq = 0;
    while start.elapsed() < ms(1000) {
        seq += 1;
        room::submit(st, &p, &a.init.client, edit(seq, seq - 1, insert(len, len, "."))).await.unwrap();
        len += 1;
        // Below the limit of 30 edits a second.
        tokio::time::sleep(ms(50)).await;
    }
    let typed = start.elapsed();
    // Let the last render land, then count what arrived.
    tokio::time::sleep(timing.render_every * 3).await;
    let mut contents = Vec::new();
    while let Ok(e) = watcher.events.try_recv() {
        if let WatchEvent::Content { html, .. } = e {
            contents.push(html);
        }
    }
    let most = typed.as_millis() / timing.render_every.as_millis() + 2;
    assert!(!contents.is_empty(), "no content while typing");
    assert!(contents.len() as u128 <= most, "{} renders in {typed:?}", contents.len());
    assert!(contents.last().unwrap().contains(&format!("hello{}", ".".repeat(usize::try_from(seq).unwrap()))));

    let closed = Instant::now();
    drop(a);
    assert_eq!(next_watch(&mut watcher.events, live).await, 0);
    assert!(closed.elapsed() >= timing.presence_grace);
}

#[tokio::test]
async fn an_unknown_client_is_forbidden() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let stranger = ClientId::from_hex(&"ab".repeat(16)).unwrap();
    let msg = || Msg::Caret { pos: 0 };
    assert!(matches!(room::submit(st, &p, &stranger, msg()).await, Err(Error::Forbidden)), "no session");
    let _a = join(st, &p, ip(1)).await;
    assert!(matches!(room::submit(st, &p, &stranger, msg()).await, Err(Error::Forbidden)), "unknown client");
    assert!(format!("{stranger:?}").find("ab").is_none(), "Debug shows the secret");
}

#[tokio::test]
async fn carets_follow_the_edits() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let a = join(st, &p, ip(1)).await;
    let mut b = join(st, &p, ip(2)).await;
    room::submit(st, &p, &a.init.client, Msg::Caret { pos: 5 }).await.unwrap();
    room::submit(st, &p, &b.init.client, Msg::Edit { seq: 1, base: 0, op: insert(5, 0, "xx"), pos: 2 }).await.unwrap();
    let want = vec![Peer { peer: a.peer, pos: 7 }, Peer { peer: b.peer, pos: 2 }];
    tokio::time::timeout(PATIENCE, async {
        loop {
            if let EditorEvent::Peers(peers) = b.events.recv().await.unwrap()
                && peers == want
            {
                return;
            }
        }
    })
    .await
    .expect("the carets were never shifted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joins_racing_to_start_a_session_share_it() {
    let app = live_app().await;
    // Several rounds, so the two joins really overlap in some of them.
    for round in 0..20 {
        let p = create(&app.st, "hello", Privacy::Unlisted).await;
        let racer = |n: u32| {
            let (st, p) = (app.st.clone(), p.clone());
            tokio::spawn(async move { join(&st, &p, ip(n)).await })
        };
        let (a, b) = (racer(2 * round), racer(2 * round + 1));
        let (a, b) = (a.await.unwrap(), b.await.unwrap());
        assert_ne!(a.peer, b.peer, "round {round}");
        assert_eq!((a.init.rev, a.init.text.as_str()), (0, "hello"));
        assert_eq!((b.init.rev, b.init.text.as_str()), (0, "hello"));
        let peers = |e: &Editor| e.init.peers.iter().map(|p| p.peer).collect::<Vec<_>>();
        // The later of the two saw the earlier in its presence row: one session, not two.
        assert!(peers(&a).contains(&b.peer) || peers(&b).contains(&a.peer), "round {round}");
    }
    assert_eq!(app.st.rooms.sessions(), 20);
}

/// The next editor event that `pick` accepts, skipping the others.
async fn next_editor<T>(rx: &mut Receiver<EditorEvent>, pick: impl Fn(EditorEvent) -> Option<T>) -> T {
    tokio::time::timeout(PATIENCE, async {
        loop {
            if let Some(t) = pick(rx.recv().await.unwrap()) {
                return t;
            }
        }
    })
    .await
    .expect("the expected editor event did not arrive")
}

async fn editor_gone(rx: &mut Receiver<EditorEvent>) {
    next_editor(rx, |e| matches!(e, EditorEvent::Gone).then_some(())).await;
}

async fn watcher_gone(rx: &mut Receiver<WatchEvent>) {
    next_watch(rx, |e| matches!(e, WatchEvent::Gone).then_some(())).await;
}

async fn row_count(st: &AppState, p: &Paste) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM pastes WHERE id = ?")
        .bind(p.id.0 as i64)
        .fetch_one(&st.pool)
        .await
        .unwrap()
}

/// Saves only when told: no idle or max-unsaved save comes during a test.
fn no_timed_saves() -> Timing {
    Timing { idle_save: Duration::from_secs(600), max_unsaved: Duration::from_secs(600), ..timing() }
}

#[tokio::test]
async fn a_form_edit_arrives_as_an_operation() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let mut a = join(st, &p, ip(1)).await;
    paste::edit(st, p.id, Access::Anonymous, ip(2), "new text".into(), Some("rust".into()), domain::now())
        .await
        .unwrap();
    let (rev, peer, seq, op) = next_op(&mut a.events).await;
    assert_eq!((rev, peer, seq), (1, 0, 0));
    assert_eq!(op.apply("hello").unwrap(), "new text");
    let syntax = next_editor(&mut a.events, |e| match e {
        EditorEvent::Syntax(s) => Some(s),
        _ => None,
    })
    .await;
    assert_eq!(syntax.as_deref(), Some("rust"));
    eventually("the row is saved", || async { row_text(st, &p).await == "new text" }).await;
    assert_eq!(paste::meta(st, p.id, domain::now()).await.unwrap().syntax.as_deref(), Some("rust"));

    // The same text with another syntax still reaches the editors and the row.
    paste::edit(st, p.id, Access::Anonymous, ip(2), "new text".into(), None, domain::now()).await.unwrap();
    let syntax = next_editor(&mut a.events, |e| match e {
        EditorEvent::Syntax(s) => Some(s),
        EditorEvent::Op { .. } => panic!("an unchanged text made an operation"),
        _ => None,
    })
    .await;
    assert_eq!(syntax, None);
    eventually("the syntax is saved", || async {
        paste::meta(st, p.id, domain::now()).await.unwrap().syntax.is_none()
    })
    .await;
}

#[tokio::test]
async fn an_edit_without_a_session_tells_watchers() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let mut watcher = room::watch(st, &p, ip(9)).unwrap();
    paste::edit(st, p.id, Access::Anonymous, ip(2), "new text".into(), None, domain::now()).await.unwrap();
    assert_eq!(row_text(st, &p).await, "new text");
    let html = next_watch(&mut watcher.events, |e| match e {
        WatchEvent::Content { html, .. } => Some(html),
        _ => None,
    })
    .await;
    assert!(html.contains("new text"), "{html}");

    let url = "https://example.org/";
    paste::edit(st, p.id, Access::Anonymous, ip(2), url.into(), None, domain::now()).await.unwrap();
    next_watch(&mut watcher.events, |e| matches!(e, WatchEvent::Reload).then_some(())).await;
}

#[tokio::test]
async fn a_wrong_password_edit_changes_nothing_live() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Private).await;
    let before = row(st, &p).await;
    let mut watcher = room::watch(st, &p, ip(9)).unwrap();
    let mut a = join_with(st, &p, ip(1), Some(dek(&p).await)).await;
    // The join's `Live` reached the watcher before the edit.
    next_watch(&mut watcher.events, |e| matches!(e, WatchEvent::Live { editors: 1 }).then_some(())).await;
    let refused =
        paste::edit(st, p.id, Access::Password("wrong".into()), ip(2), "new text".into(), None, domain::now()).await;
    assert!(matches!(refused, Err(Error::Forbidden)), "{refused:?}");
    // Long enough for a save and a render to have happened.
    tokio::time::sleep(timing().max_unsaved).await;
    assert!(matches!(a.events.try_recv(), Err(tokio::sync::broadcast::error::TryRecvError::Empty)));
    assert!(matches!(watcher.events.try_recv(), Err(tokio::sync::broadcast::error::TryRecvError::Empty)));
    assert_eq!(row(st, &p).await, before);
}

#[tokio::test]
async fn delete_tells_everyone() {
    let app = support::app_with_timing(CONFIG, no_timed_saves()).await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let mut watcher = room::watch(st, &p, ip(9)).unwrap();
    let mut a = join(st, &p, ip(1)).await;
    room::submit(st, &p, &a.init.client, edit(1, 0, insert(5, 5, "!"))).await.unwrap();
    paste::delete(st, p.id, paste::DeleteAuth::None, ip(2), domain::now()).await.unwrap();
    editor_gone(&mut a.events).await;
    watcher_gone(&mut watcher.events).await;
    let refused = room::submit(st, &p, &a.init.client, edit(2, 1, insert(6, 6, "!"))).await;
    assert!(matches!(refused, Err(Error::Forbidden)), "{refused:?}");
    assert_eq!(st.rooms.sessions(), 0, "the session was dropped");
    room::flush_all(st).await;
    assert_eq!(row_count(st, &p).await, 0, "a row was written after the delete");
}

#[tokio::test]
async fn expiry_tells_everyone() {
    let app = live_app().await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let mut watcher = room::watch(st, &p, ip(9)).unwrap();
    let mut a = join(st, &p, ip(1)).await;
    assert_eq!(paste::purge(st, p.expires_at.unwrap() + 1).await.unwrap(), 1);
    editor_gone(&mut a.events).await;
    watcher_gone(&mut watcher.events).await;
    assert_eq!(st.rooms.sessions(), 0, "the session was dropped");
}

#[tokio::test]
async fn a_new_paste_at_the_address_never_meets_the_old_room() {
    let app = support::app_with_timing(CONFIG, no_timed_saves()).await;
    let st = &app.st;
    paste::set_id_source(vec![42]);
    let old = create(st, "hello", Privacy::Unlisted).await;
    let mut a = join(st, &old, ip(1)).await;
    room::submit(st, &old, &a.init.client, edit(1, 0, insert(5, 5, "!"))).await.unwrap();
    paste::delete(st, old.id, paste::DeleteAuth::None, ip(2), domain::now()).await.unwrap();
    editor_gone(&mut a.events).await;

    paste::set_id_source(vec![42]);
    let new = NewPaste {
        content: "fresh".into(),
        privacy: Privacy::Unlisted,
        expiry: Expiry::Hour24,
        burn_after_reads: 0,
        syntax: None,
        editable: true,
        password: None,
        secret: None,
    };
    let id = paste::create(st, new, None, old.created_at + 5).await.unwrap();
    assert_eq!(id, old.id);
    let new = paste::meta(st, id, domain::now()).await.unwrap();
    assert_ne!(new.created_at, old.created_at);

    let refused = room::submit(st, &old, &a.init.client, edit(2, 1, insert(6, 6, "!"))).await;
    assert!(matches!(refused, Err(Error::Forbidden)), "{refused:?}");
    let b = join(st, &new, ip(3)).await;
    assert_eq!((b.init.rev, b.init.text.as_str()), (0, "fresh"));
    let refused = room::submit(st, &new, &a.init.client, edit(2, 0, insert(5, 5, "!"))).await;
    assert!(matches!(refused, Err(Error::Forbidden)), "{refused:?}");
    room::flush_all(st).await;
    assert_eq!(row_text(st, &new).await, "fresh");
}

#[tokio::test]
async fn flush_all_saves_now() {
    let app = support::app_with_timing(CONFIG, no_timed_saves()).await;
    let st = &app.st;
    let p = create(st, "hello", Privacy::Unlisted).await;
    let a = join(st, &p, ip(1)).await;
    room::submit(st, &p, &a.init.client, edit(1, 0, insert(5, 5, "!"))).await.unwrap();
    room::flush_all(st).await;
    assert_eq!(row_text(st, &p).await, "hello!");
}
