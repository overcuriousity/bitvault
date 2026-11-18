//! Live edit over HTTP: the editor's event stream, the route its messages are posted to, and the
//! stream an open read view follows. Thin adapters over `domain::live::room`.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time::{Interval, MissedTickBehavior};

use super::paste_id;
use crate::domain::crypto::Dek;
use crate::domain::grant::{self, GrantKey};
use crate::domain::live::ot::Op;
use crate::domain::live::room::{self, ClientId, EditorEvent, Init, Joined, Msg, StreamGuard, WatchEvent, Watching};
use crate::domain::paste::{self, Paste};
use crate::domain::words::PasteId;
use crate::domain::{self, Privacy};
use crate::error::Error;
use crate::security::ClientIp;
use crate::state::AppState;

/// The header that carries an editor's client secret on its posts.
pub const CLIENT_HEADER: &str = "x-live-client";
/// A comment line this often keeps proxies from closing a quiet stream.
const KEEP_ALIVE: Duration = Duration::from_secs(20);
const EVENT_STREAM: &str = "text/event-stream";

/// `GET /{words}/live/events` and `GET /{words}/events`, for the rest group: its timeout covers
/// the response headers only, so a stream may stay open.
pub fn routes() -> Router<AppState> {
    Router::new().route("/{words}/live/events", get(editor_events)).route("/{words}/events", get(watch_events))
}

/// `POST /{words}/live`, for the edits group, whose body limit fits a whole paste's text.
pub fn edit_routes() -> Router<AppState> {
    Router::new().route("/{words}/live", post(submit))
}

/// The paste at `words` if it is edited live; any other is not found.
async fn live_paste(st: &AppState, words: &str, now: i64) -> Result<Paste, Error> {
    let p = paste::meta(st, paste_id(words)?, now).await?;
    if paste::live(st, &p) { Ok(p) } else { Err(Error::NotFound) }
}

#[derive(Deserialize)]
struct EventsQuery {
    /// A private paste's grant, needed on every connect.
    g: Option<String>,
    /// A reconnecting editor's secret.
    client: Option<String>,
}

/// The client and revision a reconnect resumes from: both `?client=` and `Last-Event-ID`, well
/// formed, or it is a fresh join.
fn resume(q: &EventsQuery, headers: &HeaderMap) -> Option<(ClientId, u64)> {
    let client = ClientId::from_hex(q.client.as_deref()?)?;
    let rev = headers.get("last-event-id")?.to_str().ok()?.trim().parse().ok()?;
    Some((client, rev))
}

/// A private paste's data key, from the grant its stream must present on every connect; `None`
/// for any other paste.
fn connect_key(st: &AppState, p: &Paste, g: Option<&str>, now: i64) -> Result<Option<Dek>, Error> {
    match p.privacy {
        Privacy::Private => {
            let g = g.ok_or(Error::Forbidden)?;
            Ok(Some(grant::check(&st.grant_key, g, p.id, now)?.ok_or(Error::GrantExpired)?))
        }
        _ => Ok(None),
    }
}

/// A private stream's grant renewal, every [`room::Timing::grant_every`], from the key its
/// connect brought.
fn renewal(st: &AppState, p: &Paste, dek: Option<&Dek>) -> Option<Renew> {
    dek.and_then(|d| Dek::from_slice(d.as_bytes())).map(|dek| {
        let every = st.rooms.timing().grant_every;
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Renew { key: Arc::clone(&st.grant_key), paste: p.id, dek, tick }
    })
}

/// The answer to a `HEAD` on a stream route: its headers, without joining or watching a room.
fn head() -> Response {
    let mut res = super::paste::head_only(EVENT_STREAM);
    res.headers_mut().insert("x-accel-buffering", HeaderValue::from_static("no"));
    res
}

/// `GET /{words}/live/events`: joins the session and streams its events. A private paste needs a
/// valid grant on every connect, known client or not; its stream hands out a fresh grant every
/// [`room::Timing::grant_every`].
async fn editor_events(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    method: Method,
    Path(words): Path<String>,
    Query(q): Query<EventsQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let now = domain::now();
    let p = live_paste(&st, &words, now).await?;
    let dek = connect_key(&st, &p, q.g.as_deref(), now)?;
    if method == Method::HEAD {
        return Ok(head());
    }
    let renew = renewal(&st, &p, dek.as_ref());
    let joined = room::join(&st, &p, dek, ip, resume(&q, &headers)).await?;
    let state = match joined {
        Joined::Full => Feed::ended(event("full", &json!({}))),
        Joined::In { init, replay, events, guard, peer: _ } => {
            let mut queue: VecDeque<Event> = init.map(init_event).into_iter().collect();
            queue.extend(replay.into_iter().map(|e| e.frame().0));
            Feed { queue, live: Some(Live { events, renew, guard }) }
        }
    };
    Ok(sse(state.into_stream()))
}

#[derive(Deserialize)]
struct WatchQuery {
    /// A private paste's grant, needed on every connect.
    g: Option<String>,
}

/// `GET /{words}/events`: an open read view's stream. It starts with `live` and, unless the
/// paste is a URL paste, the current `content`; then it follows the editor count and the text,
/// and tells of a change of kind (`reload`) or the paste's end (`gone`). Pushed text is not a
/// read. A private paste needs a valid grant on every connect, and gets fresh ones as the
/// editor's stream does.
async fn watch_events(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    method: Method,
    Path(words): Path<String>,
    Query(q): Query<WatchQuery>,
) -> Result<Response, Error> {
    let now = domain::now();
    let p = live_paste(&st, &words, now).await?;
    let dek = connect_key(&st, &p, q.g.as_deref(), now)?;
    if method == Method::HEAD {
        return Ok(head());
    }
    let renew = renewal(&st, &p, dek.as_ref());
    // Subscribed before the text is taken, so no change falls between them.
    let mut watching = room::watch(&st, &p, ip)?;
    let mut queue = VecDeque::from([WatchEvent::Live { editors: watching.editors }.frame().0]);
    queue.extend(watching.content(&st, &p, dek.as_ref()).await?.map(|e| e.frame().0));
    let Watching { events, guard, .. } = watching;
    Ok(sse(Feed { queue, live: Some(Live { events, renew, guard }) }.into_stream()))
}

fn sse(stream: impl Stream<Item = Result<Event, Infallible>> + Send + 'static) -> Response {
    let mut res = Sse::new(stream).keep_alive(KeepAlive::new().interval(KEEP_ALIVE)).into_response();
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    res
}

/// An event a stream carries, as its frame, and whether the stream ends after it.
trait Frame {
    fn frame(self) -> (Event, bool);
}

/// What a stream still has to send: the frames queued, then what arrives while it is live.
struct Feed<E> {
    queue: VecDeque<Event>,
    /// `None` once the stream ends after its queue.
    live: Option<Live<E>>,
}

struct Live<E> {
    events: broadcast::Receiver<E>,
    renew: Option<Renew>,
    /// Dropped with the stream when the client goes: the editor leaves, the watcher stops
    /// counting. It also tells when every stream must end, for a shutdown.
    guard: StreamGuard,
}

/// A private stream's grant renewal, from the data key its connect grant carried.
struct Renew {
    key: Arc<GrantKey>,
    paste: PasteId,
    dek: Dek,
    tick: Interval,
}

impl Feed<EditorEvent> {
    fn ended(last: Event) -> Self {
        Self { queue: VecDeque::from([last]), live: None }
    }
}

impl<E: Frame + Clone + Send + 'static> Feed<E> {
    fn into_stream(self) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
        futures_util::stream::unfold(self, |mut feed| async move {
            let event = feed.next().await?;
            Some((Ok(event), feed))
        })
    }

    async fn next(&mut self) -> Option<Event> {
        if let Some(e) = self.queue.pop_front() {
            return Some(e);
        }
        let live = self.live.as_mut()?;
        let next = tokio::select! {
            got = live.events.recv() => match got {
                Ok(e) => Some(e.frame()),
                // A lagging stream ends; the client reconnects and is replayed or re-inited.
                Err(RecvError::Lagged(_) | RecvError::Closed) => None,
            },
            () = tick(&mut live.renew) => live.renew.as_ref().map(|r| {
                let g = grant::issue(&r.key, r.paste, Some(&r.dek), domain::now());
                (event("grant", &json!({ "g": g })), false)
            }),
            // A shutdown ends the stream; the client reconnects once the server runs again.
            () = live.guard.closed() => None,
        };
        match next {
            Some((e, last)) => {
                if last {
                    self.live = None;
                }
                Some(e)
            }
            None => {
                self.live = None;
                None
            }
        }
    }
}

/// The next renewal, or never for a stream without one.
async fn tick(renew: &mut Option<Renew>) {
    match renew {
        Some(r) => {
            r.tick.tick().await;
        }
        None => std::future::pending().await,
    }
}

fn event(name: &str, data: &impl Serialize) -> Event {
    // Serialising these plain values cannot fail; an empty object stands in if it ever did.
    Event::default().event(name).data(serde_json::to_string(data).unwrap_or_else(|_| "{}".into()))
}

/// `init`, with the stream's own secret; its id is its revision, so a reconnect right after it
/// can resume.
fn init_event(init: Init) -> Event {
    let data = json!({
        "client": init.client.to_hex(),
        "peer": init.peer,
        "rev": init.rev,
        "text": init.text,
        "syntax": init.syntax,
        "peers": init.peers,
    });
    event("init", &data).id(init.rev.to_string())
}

impl Frame for EditorEvent {
    fn frame(self) -> (Event, bool) {
        match self {
            Self::Op { rev, peer, seq, op } => {
                (event("op", &json!({ "rev": rev, "peer": peer, "seq": seq, "op": op })).id(rev.to_string()), false)
            }
            Self::Peers(peers) => (event("peers", &peers), false),
            Self::Syntax(syntax) => (event("syntax", &json!({ "syntax": syntax })), false),
            Self::Gone => (event("gone", &json!({})), true),
        }
    }
}

impl Frame for WatchEvent {
    fn frame(self) -> (Event, bool) {
        match self {
            Self::Live { editors } => (event("live", &json!({ "editors": editors })), false),
            Self::Content { html, highlighted } => {
                (event("content", &json!({ "html": html, "highlighted": highlighted })), false)
            }
            // The page loads again; the stream stays open until it does.
            Self::Reload => (event("reload", &json!({})), false),
            Self::Gone => (event("gone", &json!({})), true),
        }
    }
}

/// One message from an editor; any other shape is refused.
#[derive(Deserialize)]
#[serde(untagged)]
enum Body {
    Edit(EditBody),
    Caret(CaretBody),
    Syntax(SyntaxBody),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditBody {
    seq: u64,
    base: u64,
    op: Op,
    pos: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaretBody {
    pos: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntaxBody {
    // Required, though it may be null.
    #[serde(deserialize_with = "Option::deserialize")]
    syntax: Option<String>,
}

const BAD_MESSAGE: &str = "The editor sent a message the server does not understand. Reload the page.";

/// `POST /{words}/live`: an editor's edit, caret move or syntax change, `204` when accepted. The
/// client secret in `X-Live-Client` is the authorisation, also for a private paste.
async fn submit(
    State(st): State<AppState>,
    Path(words): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, Error> {
    let p = live_paste(&st, &words, domain::now()).await?;
    let client = headers
        .get(CLIENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(ClientId::from_hex)
        .ok_or(Error::Forbidden)?;
    let msg = match serde_json::from_slice(&body).map_err(|_| Error::Invalid(BAD_MESSAGE.into()))? {
        Body::Edit(EditBody { seq, base, op, pos }) => Msg::Edit { seq, base, op, pos },
        Body::Caret(CaretBody { pos }) => Msg::Caret { pos },
        Body::Syntax(SyntaxBody { syntax: None }) => Msg::Syntax(None),
        Body::Syntax(SyntaxBody { syntax: Some(s) }) => Msg::Syntax(super::home::parse_syntax(&s)?),
    };
    room::submit(&st, &p, &client, msg).await?;
    Ok(StatusCode::NO_CONTENT)
}
