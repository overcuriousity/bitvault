//! Rooms: the in-memory state of the pastes being edited live or watched.
//!
//! A room belongs to one paste, keyed by its address and creation time, so a paste that later
//! takes over the address never meets an old room. It holds a channel for editors and one for
//! watchers (read views) and, while editors are present, the session: the text in one order
//! (each edit transformed over the ones it crossed), the operations since the session began, the
//! clients it has had, and a private paste's data key. A task per session saves the text, renders
//! it for watchers and ends the session after the last editor left. The session's logic is in
//! `session.rs`, its task in `task.rs`.
//!
//! Locking: [`Rooms`] has one lock over the map and the counts, each room one over its state.
//! The map's is always taken first, and neither is held across an `.await`.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::sync::{Notify, broadcast};
use tokio::time::Instant;

use super::ot::Op;
use super::session::Session;
use super::task::run;
use crate::domain::crypto::{Dek, random_bytes};
use crate::domain::paste::{self, Paste};
use crate::domain::words::PasteId;
use crate::domain::{self, Privacy};
use crate::error::Error;
use crate::ratelimit::bucket_key;
use crate::state::AppState;

const EDITORS: usize = 64;
const WATCHERS: usize = 256;
/// Editor and watcher streams together, across all pastes, per client address.
const STREAMS_PER_ADDRESS: usize = 16;
const SESSIONS: usize = 512;
const HISTORY_REVS: usize = 10_000;
const HISTORY_BYTES: usize = 8 << 20;
const EDITOR_CHANNEL: usize = 1024;
const WATCH_CHANNEL: usize = 64;

/// The delays of saving, presence and throttling.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Save once the text has been unchanged this long...
    pub idle_save: Duration,
    /// ...and at the latest this long after the first unsaved change.
    pub max_unsaved: Duration,
    /// The session ends this long after the last editor's stream closed.
    pub session_grace: Duration,
    /// An editor whose stream closed stays in the presence row this long.
    pub presence_grace: Duration,
    /// Watchers get the rendered text at most this often.
    pub render_every: Duration,
    /// Editors get caret moves at most this often.
    pub peers_every: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            idle_save: Duration::from_secs(2),
            max_unsaved: Duration::from_secs(10),
            session_grace: Duration::from_secs(60),
            presence_grace: Duration::from_secs(15),
            render_every: Duration::from_secs(1),
            peers_every: Duration::from_millis(250),
        }
    }
}

/// An editor's 128-bit secret; holding it is the right to submit. Compared in constant time and
/// never printed.
#[derive(Clone)]
pub struct ClientId([u8; 16]);

impl ClientId {
    pub fn random() -> Self {
        Self(random_bytes())
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let mut out = [0; 16];
        hex::decode_to_slice(s, &mut out).ok()?;
        Some(Self(out))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl PartialEq for ClientId {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for ClientId {}

impl fmt::Debug for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientId(..)")
    }
}

/// An editor in the presence row: its public number and caret position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Peer {
    pub peer: u32,
    pub pos: u32,
}

#[derive(Debug, Clone)]
pub enum EditorEvent {
    /// The operation that made revision `rev`; a server edit has `peer` and `seq` 0.
    Op {
        rev: u64,
        peer: u32,
        seq: u64,
        op: Op,
    },
    Peers(Vec<Peer>),
    Syntax(Option<String>),
    /// The paste was deleted or expired.
    Gone,
}

#[derive(Debug, Clone)]
pub enum WatchEvent {
    Live {
        editors: usize,
    },
    /// The text as the paste page renders it.
    Content {
        html: String,
        highlighted: bool,
    },
    /// The paste changed between text and URL: the page must be loaded again.
    Reload,
    Gone,
}

/// What a joining editor starts from.
pub struct Init {
    pub client: ClientId,
    pub peer: u32,
    pub rev: u64,
    pub text: String,
    pub syntax: Option<String>,
    pub peers: Vec<Peer>,
}

pub enum Joined {
    /// The paste has [`EDITORS`] editors already.
    Full,
    /// `init` is `None` exactly when `replay` brings a known client up to date.
    In {
        init: Option<Init>,
        replay: Vec<EditorEvent>,
        events: broadcast::Receiver<EditorEvent>,
        guard: StreamGuard,
        peer: u32,
    },
}

/// What an editor sends.
#[derive(Debug, Clone)]
pub enum Msg {
    /// An edit made against revision `base`; `pos` is the caret in the text it made.
    Edit {
        seq: u64,
        base: u64,
        op: Op,
        pos: u32,
    },
    Caret {
        pos: u32,
    },
    Syntax(Option<String>),
}

pub struct Watching {
    pub editors: usize,
    pub events: broadcast::Receiver<WatchEvent>,
    pub guard: StreamGuard,
}

type Key = (PasteId, i64);

fn key(p: &Paste) -> Key {
    (p.id, p.created_at)
}

pub(super) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock only means another request panicked; the state is still consistent.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The rooms of all pastes with a stream or a session.
pub struct Rooms {
    pub(super) timing: Timing,
    history_revs: usize,
    history_bytes: usize,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    rooms: HashMap<Key, Arc<Room>>,
    streams: HashMap<IpAddr, usize>,
    sessions: usize,
}

impl Rooms {
    pub fn new(timing: Timing) -> Arc<Self> {
        Arc::new(Self { timing, history_revs: HISTORY_REVS, history_bytes: HISTORY_BYTES, inner: Mutex::default() })
    }

    /// Rooms whose sessions keep fewer operations. Test-only.
    #[cfg(feature = "test-hooks")]
    pub fn with_history(timing: Timing, revs: usize, bytes: usize) -> Arc<Self> {
        Arc::new(Self { timing, history_revs: revs, history_bytes: bytes, inner: Mutex::default() })
    }

    /// How many sessions are running.
    pub fn sessions(&self) -> usize {
        lock(&self.inner).sessions
    }

    fn room(&self, key: Key) -> Option<Arc<Room>> {
        lock(&self.inner).rooms.get(&key).cloned()
    }

    /// Counts a new stream from `ip` into the room of `key`, creating the room. The cap of
    /// [`STREAMS_PER_ADDRESS`] counts an IPv6 client by its /64 ([`bucket_key`]), as the rate
    /// limiters do, since one subscriber usually holds the whole block.
    fn reserve(self: &Arc<Self>, key: Key, ip: IpAddr) -> Result<StreamGuard, Error> {
        let ip = bucket_key(ip);
        let mut inner = lock(&self.inner);
        let streams = inner.streams.entry(ip).or_default();
        if *streams >= STREAMS_PER_ADDRESS {
            return Err(Error::TooManyAttempts);
        }
        *streams += 1;
        let room = Arc::clone(inner.rooms.entry(key).or_insert_with(|| Arc::new(Room::new(key))));
        lock(&room.state).streams += 1;
        Ok(StreamGuard { rooms: Arc::clone(self), room, ip, role: Role::Pending })
    }

    fn reserve_session(self: &Arc<Self>) -> Result<SessionSlot, Error> {
        let mut inner = lock(&self.inner);
        if inner.sessions >= SESSIONS {
            return Err(Error::TooManyAttempts);
        }
        inner.sessions += 1;
        Ok(SessionSlot(Some(Arc::clone(self))))
    }

    /// Ends `room`'s session if `done` still says so with both locks held. Removes the room when
    /// no stream is left.
    pub(super) fn end(&self, room: &Arc<Room>, done: impl FnOnce(&RoomState) -> bool, gone: bool) -> bool {
        let mut inner = lock(&self.inner);
        let mut s = lock(&room.state);
        if s.session.is_none() || !done(&s) {
            return false;
        }
        s.session = None;
        inner.sessions -= 1;
        if gone {
            let _ = room.editors.send(EditorEvent::Gone);
            let _ = room.watchers.send(WatchEvent::Gone);
        }
        s.sync_live(room);
        if s.streams == 0 {
            inner.remove(room);
        }
        true
    }
}

impl Inner {
    fn remove(&mut self, room: &Arc<Room>) {
        if self.rooms.get(&room.key).is_some_and(|r| Arc::ptr_eq(r, room)) {
            self.rooms.remove(&room.key);
        }
    }
}

/// A counted session that is still being loaded; dropping it gives the count back.
struct SessionSlot(Option<Arc<Rooms>>);

impl SessionSlot {
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        if let Some(rooms) = self.0.take() {
            lock(&rooms.inner).sessions -= 1;
        }
    }
}

enum Role {
    Pending,
    Watcher,
    Editor(u32),
}

/// An open stream. Dropping it closes the stream: the counts go down, an editor's presence and
/// the session's end are timed from here, and the last stream of a room without a session
/// removes the room.
pub struct StreamGuard {
    rooms: Arc<Rooms>,
    room: Arc<Room>,
    ip: IpAddr,
    role: Role,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let now = Instant::now();
        let mut inner = lock(&self.rooms.inner);
        if let Some(n) = inner.streams.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                inner.streams.remove(&self.ip);
            }
        }
        let mut s = lock(&self.room.state);
        s.streams -= 1;
        match self.role {
            Role::Pending => {}
            Role::Watcher => s.watchers -= 1,
            Role::Editor(peer) => {
                s.editor_streams -= 1;
                let alone = s.editor_streams == 0;
                if let Some(sess) = s.session.as_mut() {
                    if let Some(c) = sess.clients.iter_mut().find(|c| c.peer == peer) {
                        c.streams -= 1;
                        if c.streams == 0 {
                            c.left_at = Some(now);
                        }
                    }
                    if alone {
                        sess.alone_since = Some(now);
                    }
                }
                self.room.wake.notify_one();
            }
        }
        if s.streams == 0 && s.session.is_none() {
            drop(s);
            inner.remove(&self.room);
        }
    }
}

pub(super) struct Room {
    pub(super) key: Key,
    pub(super) editors: broadcast::Sender<EditorEvent>,
    pub(super) watchers: broadcast::Sender<WatchEvent>,
    /// Wakes the session task when something it times has changed.
    pub(super) wake: Notify,
    pub(super) state: Mutex<RoomState>,
}

#[derive(Default)]
pub(super) struct RoomState {
    /// Every counted stream, including those still joining.
    pub(super) streams: usize,
    pub(super) watchers: usize,
    pub(super) editor_streams: usize,
    /// The editor count watchers were last told.
    pub(super) live_sent: usize,
    pub(super) session: Option<Session>,
}

impl Room {
    fn new(key: Key) -> Self {
        Self {
            key,
            editors: broadcast::channel(EDITOR_CHANNEL).0,
            watchers: broadcast::channel(WATCH_CHANNEL).0,
            wake: Notify::new(),
            state: Mutex::default(),
        }
    }
}

impl RoomState {
    /// Tells watchers the editor count when it changed.
    pub(super) fn sync_live(&mut self, room: &Room) {
        let editors = self.session.as_ref().map_or(0, Session::present);
        if editors != self.live_sent {
            self.live_sent = editors;
            let _ = room.watchers.send(WatchEvent::Live { editors });
        }
    }

    /// Adds an editor stream to the running session, subscribing and taking the snapshot under
    /// this one lock.
    fn enter(&mut self, room: &Room, dek: Option<&Dek>, resume: Option<&(ClientId, u64)>) -> Result<Entered, Error> {
        let full = self.editor_streams >= EDITORS;
        let Some(sess) = self.session.as_mut() else { return Err(Error::internal("no session to enter")) };
        if let (Some(ours), Some(given)) = (sess.dek.as_deref(), dek)
            && ours != given
        {
            return Err(Error::Forbidden);
        }
        if full {
            return Ok(Entered::Full);
        }
        let now = Instant::now();
        let known = resume.and_then(|(id, rev)| Some((sess.clients.iter().position(|c| c.id == *id)?, *rev)));
        let (idx, replay) = match known {
            Some((idx, rev)) => (idx, sess.replay(rev)),
            None => (sess.add_client(now), None),
        };
        let client = &mut sess.clients[idx];
        client.streams += 1;
        client.present = true;
        client.left_at = None;
        let peer = client.peer;
        sess.alone_since = None;
        let _ = room.editors.send(EditorEvent::Peers(sess.peers()));
        let events = room.editors.subscribe();
        let (init, replay) = match replay {
            Some(replay) => (None, replay),
            None => (Some(sess.init(idx)), Vec::new()),
        };
        self.editor_streams += 1;
        self.sync_live(room);
        Ok(Entered::In { init, replay, events, peer })
    }
}

/// [`Joined`] before the stream's guard is added.
enum Entered {
    Full,
    In { init: Option<Init>, replay: Vec<EditorEvent>, events: broadcast::Receiver<EditorEvent>, peer: u32 },
}

/// Joins an editor to the paste's session, starting the session if there is none. A private
/// paste needs its data key. `resume` is a client this session may know and the last revision it
/// applied; when the operations since are still kept, they are replayed instead of an init.
pub async fn join(
    st: &AppState,
    p: &Paste,
    dek: Option<Dek>,
    ip: IpAddr,
    resume: Option<(ClientId, u64)>,
) -> Result<Joined, Error> {
    if !paste::live(st, p) || (p.privacy == Privacy::Private && dek.is_none()) {
        return Err(Error::Forbidden);
    }
    let dek = dek.map(Arc::new);
    let mut guard = st.rooms.reserve(key(p), ip)?;
    let room = Arc::clone(&guard.room);
    // At most twice: a session another join started meanwhile is entered on the next turn.
    loop {
        {
            let mut s = lock(&room.state);
            if s.session.is_some() {
                let entered = s.enter(&room, dek.as_deref(), resume.as_ref());
                drop(s);
                // On a refusal the guard drops here, after the room's lock was released.
                return Ok(match entered? {
                    Entered::Full => Joined::Full,
                    Entered::In { init, replay, events, peer } => {
                        // The editor stream was counted under the lock just released; nothing
                        // awaits in between, so the guard always takes it over.
                        guard.role = Role::Editor(peer);
                        Joined::In { init, replay, events, guard, peer }
                    }
                });
            }
        }
        let slot = st.rooms.reserve_session()?;
        let (paste, text) =
            paste::peek_text(st, p.id, p.created_at, dek.as_deref(), domain::now()).await?.ok_or(Error::NotFound)?;
        let started = {
            let mut s = lock(&room.state);
            let start = s.session.is_none();
            if start {
                s.session = Some(Session::new(paste, dek.clone(), &text, Instant::now()));
                tokio::spawn(run(st.clone(), Arc::clone(&room)));
            }
            start
        };
        if started {
            slot.keep();
        }
    }
}

/// Opens a watcher stream on a live paste.
pub fn watch(st: &AppState, p: &Paste, ip: IpAddr) -> Result<Watching, Error> {
    if !paste::live(st, p) {
        return Err(Error::Forbidden);
    }
    let mut guard = st.rooms.reserve(key(p), ip)?;
    let room = Arc::clone(&guard.room);
    let mut s = lock(&room.state);
    if s.watchers >= WATCHERS {
        drop(s);
        return Err(Error::TooManyAttempts);
    }
    s.watchers += 1;
    guard.role = Role::Watcher;
    let events = room.watchers.subscribe();
    let editors = s.session.as_ref().map_or(0, Session::present);
    drop(s);
    Ok(Watching { editors, events, guard })
}

/// Applies an editor's message to the session. The stream, not the answer, tells the editor
/// that its edit was applied; a `seq` already applied is accepted and ignored.
pub async fn submit(st: &AppState, p: &Paste, client: &ClientId, msg: Msg) -> Result<(), Error> {
    let room = st.rooms.room(key(p)).ok_or(Error::Forbidden)?;
    let limits = (st.rooms.history_revs, st.rooms.history_bytes);
    let now = Instant::now();
    {
        let mut s = lock(&room.state);
        let sess = s.session.as_mut().ok_or(Error::Forbidden)?;
        let idx = sess.clients.iter().position(|c| c.id == *client).ok_or(Error::Forbidden)?;
        match msg {
            Msg::Caret { pos } => {
                sess.clients[idx].pos = pos.min(sess.len);
                sess.peers_pending = true;
            }
            Msg::Syntax(syntax) => {
                sess.clients[idx].take_token(now)?;
                if sess.syntax != syntax {
                    sess.syntax.clone_from(&syntax);
                    sess.changed(now);
                    let _ = room.editors.send(EditorEvent::Syntax(syntax));
                }
            }
            Msg::Edit { seq, base, op, pos } => {
                if seq <= sess.clients[idx].seq {
                    return Ok(());
                }
                sess.clients[idx].take_token(now)?;
                let event = sess.apply(idx, (seq, base, op, pos), limits, now)?;
                let _ = room.editors.send(event);
            }
        }
    }
    room.wake.notify_one();
    Ok(())
}
