//! A live session: the text in one order, the operations kept since it began, and the clients it
//! has had. Plain logic over owned data; the room's lock guards it.

use std::collections::VecDeque;
use std::sync::Arc;

use tokio::time::Instant;

use super::ot::{self, Op, Part};
use super::room::{ClientId, EditorEvent, Init, Peer};
use crate::domain::crypto::Dek;
use crate::domain::paste::{self, Paste, TEXT_LIMIT};
use crate::error::Error;

/// Edits and syntax changes per editor and second, also the burst.
const EDITS_PER_SECOND: f64 = 30.0;
/// The most clients one session remembers. Past it, [`Session::add_client`] forgets the one
/// absent longest, so repeated fresh joins cannot grow a long session's memory without bound.
const CLIENTS: usize = 4096;

pub(super) fn chars(s: &str) -> u32 {
    u32::try_from(s.chars().count()).unwrap_or(u32::MAX)
}

/// Live text is LF only: CRLF and a lone CR become LF.
pub(super) fn lf(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

pub(super) struct Client {
    pub(super) id: ClientId,
    pub(super) peer: u32,
    /// The last `seq` applied.
    pub(super) seq: u64,
    pub(super) pos: u32,
    pub(super) streams: usize,
    /// In the presence row: a stream is open or closed less than the presence grace ago.
    pub(super) present: bool,
    pub(super) left_at: Option<Instant>,
    pub(super) tokens: f64,
    pub(super) refilled: Instant,
}

impl Client {
    pub(super) fn take_token(&mut self, now: Instant) -> Result<(), Error> {
        let refill = now.duration_since(self.refilled).as_secs_f64() * EDITS_PER_SECOND;
        self.tokens = (self.tokens + refill).min(EDITS_PER_SECOND);
        self.refilled = now;
        if self.tokens < 1.0 {
            return Err(Error::TooManyAttempts);
        }
        self.tokens -= 1.0;
        Ok(())
    }
}

/// An applied operation, kept to transform late edits over and to replay.
pub(super) struct Logged {
    pub(super) peer: u32,
    pub(super) seq: u64,
    pub(super) op: Op,
}

/// A save taken from the session: what to write, and since when it was unsaved.
pub(super) struct Save {
    pub(super) paste: Paste,
    pub(super) dek: Option<Arc<Dek>>,
    pub(super) text: String,
    pub(super) syntax: Option<String>,
    pub(super) since: Instant,
}

pub(super) struct Session {
    pub(super) paste: Paste,
    pub(super) dek: Option<Arc<Dek>>,
    pub(super) text: String,
    pub(super) len: u32,
    pub(super) rev: u64,
    pub(super) syntax: Option<String>,
    /// The operations that made the last `history.len()` revisions.
    pub(super) history: VecDeque<Logged>,
    pub(super) history_bytes: usize,
    pub(super) clients: Vec<Client>,
    pub(super) next_peer: u32,
    pub(super) unsaved_since: Option<Instant>,
    pub(super) changed_at: Instant,
    pub(super) saving: bool,
    pub(super) retry_at: Option<Instant>,
    pub(super) render_pending: bool,
    pub(super) rendered_at: Option<Instant>,
    pub(super) peers_pending: bool,
    pub(super) peers_at: Option<Instant>,
    /// Since when no editor stream is open.
    pub(super) alone_since: Option<Instant>,
}

impl Session {
    pub(super) fn new(paste: Paste, dek: Option<Arc<Dek>>, text: &str, now: Instant) -> Self {
        let text = lf(text);
        Self {
            len: chars(&text),
            syntax: paste.syntax.clone(),
            paste,
            dek,
            text,
            rev: 0,
            history: VecDeque::new(),
            history_bytes: 0,
            clients: Vec::new(),
            next_peer: 0,
            unsaved_since: None,
            changed_at: now,
            saving: false,
            retry_at: None,
            render_pending: false,
            rendered_at: None,
            peers_pending: false,
            peers_at: None,
            alone_since: None,
        }
    }

    pub(super) fn present(&self) -> usize {
        self.clients.iter().filter(|c| c.present).count()
    }

    pub(super) fn peers(&self) -> Vec<Peer> {
        self.clients.iter().filter(|c| c.present).map(|c| Peer { peer: c.peer, pos: c.pos }).collect()
    }

    pub(super) fn init(&self, idx: usize) -> Init {
        let c = &self.clients[idx];
        Init {
            client: c.id.clone(),
            peer: c.peer,
            rev: self.rev,
            text: self.text.clone(),
            syntax: self.syntax.clone(),
            peers: self.peers(),
        }
    }

    pub(super) fn add_client(&mut self, now: Instant) -> usize {
        if self.clients.len() >= CLIENTS
            && let Some(oldest) = self
                .clients
                .iter()
                .enumerate()
                .filter(|(_, c)| !c.present)
                .min_by_key(|(_, c)| c.left_at)
                .map(|(i, _)| i)
        {
            self.clients.remove(oldest);
        }
        self.next_peer += 1;
        self.clients.push(Client {
            id: ClientId::random(),
            peer: self.next_peer,
            seq: 0,
            pos: 0,
            streams: 0,
            present: false,
            left_at: None,
            tokens: EDITS_PER_SECOND,
            refilled: now,
        });
        self.clients.len() - 1
    }

    /// The revision the oldest kept operation applies to.
    pub(super) fn first_rev(&self) -> u64 {
        self.rev - self.history.len() as u64
    }

    /// The operations after revision `since`, or `None` when they are no longer all kept.
    pub(super) fn replay(&self, since: u64) -> Option<Vec<EditorEvent>> {
        let first = self.first_rev();
        if !(first..=self.rev).contains(&since) {
            return None;
        }
        let skip = usize::try_from(since - first).ok()?;
        let events = self.history.iter().enumerate().skip(skip).map(|(i, l)| EditorEvent::Op {
            rev: first + i as u64 + 1,
            peer: l.peer,
            seq: l.seq,
            op: l.op.clone(),
        });
        Some(events.collect())
    }

    pub(super) fn changed(&mut self, now: Instant) {
        self.unsaved_since.get_or_insert(now);
        self.changed_at = now;
        self.render_pending = true;
    }

    /// Takes the unsaved text for a save and marks the session as saving; the caller checks that
    /// no save is being written. `None` when nothing is unsaved, or when the text is empty on a
    /// paste without files, which is not saved: the last text stays.
    pub(super) fn take_save(&mut self) -> Option<Save> {
        let since = self.unsaved_since.take()?;
        paste::require_content(&self.text, !self.paste.files.is_empty()).ok()?;
        self.saving = true;
        Some(Save {
            paste: self.paste.clone(),
            dek: self.dek.clone(),
            text: self.text.clone(),
            syntax: self.syntax.clone(),
            since,
        })
    }

    /// Transforms `op`, made against `base`, over everything after it and applies it.
    pub(super) fn apply(
        &mut self,
        idx: usize,
        edit: (u64, u64, Op, u32),
        limits: (usize, usize),
        now: Instant,
    ) -> Result<EditorEvent, Error> {
        let (seq, base, mut op, mut pos) = edit;
        let invalid = || Error::Invalid("The edit does not fit the text. Reload the page.".into());
        if op.parts().iter().any(|p| matches!(p, Part::Insert(s) if s.contains('\r'))) {
            return Err(invalid());
        }
        let first = self.first_rev();
        if base > self.rev || base < first {
            return Err(invalid());
        }
        let skip = usize::try_from(base - first).map_err(|_| invalid())?;
        for logged in self.history.iter().skip(skip) {
            let (theirs, mine) = ot::transform(&logged.op, &op).map_err(|_| invalid())?;
            pos = shift(pos, &theirs);
            op = mine;
        }
        let text = op.apply(&self.text).map_err(|_| invalid())?;
        if text.len() > TEXT_LIMIT && text.len() > self.text.len() {
            return Err(Error::TooLarge);
        }
        let peer = self.clients[idx].peer;
        let event = self.commit(peer, seq, op, text, limits, now);
        let client = &mut self.clients[idx];
        client.seq = seq;
        client.pos = pos.min(self.len);
        Ok(event)
    }

    /// Replaces the whole text and the syntax, as a form or API edit does. A changed text is one
    /// server edit (`peer` and `seq` 0) against the current text, so whatever changed inside the
    /// span it replaces is overwritten; the events are for the editors.
    pub(super) fn replace(
        &mut self,
        text: &str,
        syntax: Option<String>,
        limits: (usize, usize),
        now: Instant,
    ) -> Vec<EditorEvent> {
        let text = lf(text);
        let mut events = Vec::new();
        if text != self.text {
            let op = Op::from_texts(&self.text, &text);
            events.push(self.commit(0, 0, op, text, limits, now));
        }
        if self.syntax != syntax {
            self.syntax.clone_from(&syntax);
            self.changed(now);
            events.push(EditorEvent::Syntax(syntax));
        }
        events
    }

    /// Makes `op` by `peer`, which turns the text into `text`, the next revision: the other
    /// editors' carets follow it and it joins the history.
    fn commit(
        &mut self,
        peer: u32,
        seq: u64,
        op: Op,
        text: String,
        limits: (usize, usize),
        now: Instant,
    ) -> EditorEvent {
        for c in self.clients.iter_mut().filter(|c| c.peer != peer) {
            c.pos = shift(c.pos, &op);
        }
        self.len = op.target_len();
        self.text = text;
        self.rev += 1;
        self.history_bytes += op.inserted_bytes();
        self.history.push_back(Logged { peer, seq, op: op.clone() });
        let (max_revs, max_bytes) = limits;
        while self.history.len() > max_revs || (self.history_bytes > max_bytes && !self.history.is_empty()) {
            if let Some(old) = self.history.pop_front() {
                self.history_bytes -= old.op.inserted_bytes();
            }
        }
        self.changed(now);
        self.peers_pending = true;
        EditorEvent::Op { rev: self.rev, peer, seq, op }
    }
}

/// Where a caret at `pos` ends up after `op`: an insert at or before it moves it right, a
/// delete before it moves it left, and a delete across it puts it at the delete's start.
fn shift(pos: u32, op: &Op) -> u32 {
    let (mut old, mut new) = (0u32, 0u32);
    for part in op.parts() {
        match part {
            Part::Keep(n) => {
                if pos < old.saturating_add(*n) {
                    return new.saturating_add(pos - old);
                }
                old = old.saturating_add(*n);
                new = new.saturating_add(*n);
            }
            Part::Delete(n) => {
                if pos < old.saturating_add(*n) {
                    return new;
                }
                old = old.saturating_add(*n);
            }
            Part::Insert(s) => new = new.saturating_add(chars(s)),
        }
    }
    new
}
