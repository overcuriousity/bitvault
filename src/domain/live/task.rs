//! The session task: saves the text, renders it for watchers, times presence and carets, and
//! ends the session after the last editor left. One per session; it stops when the session ends.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::room::{EditorEvent, Room, RoomState, Rooms, Timing, WatchEvent, lock};
use super::session::Save;
use crate::domain::paste;
use crate::domain::{self, Kind, highlight};
use crate::error::Error;
use crate::state::AppState;

/// How often [`flush`] looks again while the task's own save is still being written.
const FLUSH_POLL: Duration = Duration::from_millis(10);

/// What the session task does next.
enum Step {
    Wait(Option<Instant>),
    Save(Box<Save>),
    Render { text: String, syntax: Option<String> },
    End,
    Exit,
}

impl Room {
    /// Decides the task's next step under the room's lock; presence and peers are sent here.
    fn plan(&self, t: &Timing, now: Instant) -> Step {
        let mut s = lock(&self.state);
        let alone = s.editor_streams == 0;
        let watched = s.watchers > 0;
        let Some(sess) = s.session.as_mut() else { return Step::Exit };
        let mut left = false;
        for c in sess.clients.iter_mut().filter(|c| c.present && c.streams == 0) {
            if c.left_at.is_some_and(|at| now >= at + t.presence_grace) {
                c.present = false;
                left = true;
            }
        }
        let peers_due = sess.peers_pending && sess.peers_at.is_none_or(|at| now >= at + t.peers_every);
        if left || peers_due {
            sess.peers_pending = false;
            sess.peers_at = Some(now);
            let _ = self.editors.send(EditorEvent::Peers(sess.peers()));
        }
        if left {
            s.sync_live(self);
        }
        let Some(sess) = s.session.as_mut() else { return Step::Exit };
        let ending = alone && sess.alone_since.is_some_and(|at| now >= at + t.session_grace);
        if let Some(since) = sess.unsaved_since
            && !sess.saving
            && sess.retry_at.is_none_or(|at| now >= at)
            && (ending || now >= sess.changed_at + t.idle_save || now >= since + t.max_unsaved)
            && let Some(save) = sess.take_save()
        {
            return Step::Save(Box::new(save));
        }
        let render_due = sess.render_pending && sess.rendered_at.is_none_or(|at| now >= at + t.render_every);
        if render_due {
            sess.render_pending = false;
            if watched && sess.paste.kind == Kind::Text {
                sess.rendered_at = Some(now);
                return Step::Render { text: sess.text.clone(), syntax: sess.syntax.clone() };
            }
        }
        if ending && sess.unsaved_since.is_none() && !sess.saving {
            return Step::End;
        }
        let mut next: Option<Instant> = None;
        let mut at = |when: Instant| next = Some(next.map_or(when, |n| n.min(when)));
        for c in sess.clients.iter().filter(|c| c.present && c.streams == 0) {
            if let Some(left_at) = c.left_at {
                at(left_at + t.presence_grace);
            }
        }
        if sess.peers_pending {
            at(sess.peers_at.map_or(now, |p| p + t.peers_every));
        }
        if let Some(since) = sess.unsaved_since.filter(|_| !sess.saving) {
            let due = (sess.changed_at + t.idle_save).min(since + t.max_unsaved);
            at(sess.retry_at.map_or(due, |r| r.max(due)));
        }
        if sess.render_pending {
            at(sess.rendered_at.map_or(now, |r| r + t.render_every));
        }
        if let Some(since) = sess.alone_since.filter(|_| alone) {
            at(since + t.session_grace);
        }
        Step::Wait(next)
    }

    /// Takes in a save's result; `false` when the session is over.
    fn saved(self: &Arc<Self>, rooms: &Rooms, result: Result<Option<Kind>, Error>, since: Instant) -> bool {
        let mut s = lock(&self.state);
        let Some(sess) = s.session.as_mut() else { return false };
        sess.saving = false;
        match result {
            Ok(Some(kind)) => {
                sess.retry_at = None;
                // A URL paste's page shows the target, not the text, so it is loaded again.
                if kind != sess.paste.kind || kind == Kind::Url {
                    let _ = self.watchers.send(WatchEvent::Reload);
                }
                sess.paste.kind = kind;
                true
            }
            Ok(None) => {
                drop(s);
                rooms.end(self, |_| true, true);
                false
            }
            Err(e) => {
                e.log();
                sess.unsaved_since = Some(sess.unsaved_since.map_or(since, |u| u.min(since)));
                sess.retry_at = Some(Instant::now() + rooms.timing.idle_save);
                true
            }
        }
    }
}

/// Writes `save` and takes in the result; `false` when the session is over.
async fn store(st: &AppState, room: &Arc<Room>, save: Save) -> bool {
    let Save { paste, dek, text, syntax, since } = save;
    let result = paste::store_text(st, &paste, dek.as_deref(), text, syntax, domain::now()).await;
    room.saved(&st.rooms, result, since)
}

/// Sends watchers `text` as the paste page renders it.
pub(super) async fn render(st: &AppState, room: &Room, text: &str, syntax: Option<&str>) {
    match highlight::content_html(st, text, syntax).await {
        Ok((html, highlighted)) => {
            let _ = room.watchers.send(WatchEvent::Content { html, highlighted });
        }
        Err(e) => e.log(),
    }
}

/// Saves `room`'s unsaved text now, after a save the task is writing, without waiting for the
/// save delays. Errors are logged; the task retries them as usual.
pub(super) async fn flush(st: &AppState, room: &Arc<Room>) {
    loop {
        let save = {
            let mut s = lock(&room.state);
            let Some(sess) = s.session.as_mut() else { return };
            // `None` while the task is writing: the newer text must not race the older one.
            (!sess.saving).then(|| sess.take_save())
        };
        match save {
            None => tokio::time::sleep(FLUSH_POLL).await,
            Some(None) => return,
            Some(Some(save)) => {
                store(st, room, save).await;
                // The task plans again: it skipped saving while this save was being written.
                room.wake.notify_one();
                return;
            }
        }
    }
}

/// The session's task: saves, renders and ends the session, and then stops.
pub(super) async fn run(st: AppState, room: Arc<Room>) {
    let rooms = Arc::clone(&st.rooms);
    let t = rooms.timing;
    loop {
        match room.plan(&t, Instant::now()) {
            Step::Wait(at) => match at {
                Some(at) => tokio::select! {
                    () = tokio::time::sleep_until(at) => {}
                    () = room.wake.notified() => {}
                },
                None => room.wake.notified().await,
            },
            Step::Save(save) => {
                if !store(&st, &room, *save).await {
                    return;
                }
            }
            Step::Render { text, syntax } => render(&st, &room, &text, syntax.as_deref()).await,
            Step::End => {
                // An editor may have come and gone, or typed, since the plan.
                let now = Instant::now();
                let done = |s: &RoomState| {
                    s.editor_streams == 0
                        && s.session.as_ref().is_some_and(|x| {
                            x.unsaved_since.is_none()
                                && !x.saving
                                && x.alone_since.is_some_and(|at| now >= at + t.session_grace)
                        })
                };
                if rooms.end(&room, done, false) {
                    return;
                }
            }
            Step::Exit => return,
        }
    }
}
