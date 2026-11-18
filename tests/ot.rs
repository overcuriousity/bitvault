#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Text operations for live edit. `fixtures/ot.json` is written by hand and is satisfied by the
//! browser's implementation too.

use std::collections::VecDeque;

use bitvault::domain::live::ot::{self, Op};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Fixture {
    apply: Vec<ApplyCase>,
    transform: Vec<TransformCase>,
    invalid: Vec<InvalidCase>,
}

#[derive(Deserialize)]
struct ApplyCase {
    text: String,
    op: Value,
    result: String,
}

#[derive(Deserialize)]
struct TransformCase {
    text: String,
    first: Value,
    second: Value,
    first2: Value,
    second2: Value,
    result: String,
}

#[derive(Deserialize)]
struct InvalidCase {
    text: String,
    op: Value,
}

fn fixture() -> Fixture {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ot.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Parses a fixture op and checks it is written in normalised form.
fn op(value: &Value) -> Op {
    let op: Op = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(&serde_json::to_value(&op).unwrap(), value, "not normalised");
    op
}

#[test]
fn fixture_apply() {
    for case in fixture().apply {
        let op = op(&case.op);
        assert_eq!(op.apply(&case.text).unwrap(), case.result, "{}", case.op);
    }
}

#[test]
fn fixture_transform() {
    for case in fixture().transform {
        let (first, second) = (op(&case.first), op(&case.second));
        let (first2, second2) = ot::transform(&first, &second).unwrap();
        let name = format!("{} / {}", case.first, case.second);
        assert_eq!(serde_json::to_value(&first2).unwrap(), case.first2, "{name}");
        assert_eq!(serde_json::to_value(&second2).unwrap(), case.second2, "{name}");
        let one = second2.apply(&first.apply(&case.text).unwrap()).unwrap();
        let two = first2.apply(&second.apply(&case.text).unwrap()).unwrap();
        assert_eq!(one, case.result, "{name}");
        assert_eq!(two, case.result, "{name}");
    }
}

#[test]
fn fixture_invalid() {
    for case in fixture().invalid {
        if let Ok(op) = serde_json::from_value::<Op>(case.op.clone()) {
            assert_eq!(op.apply(&case.text), Err(ot::OtError::Length), "{}", case.op);
        }
    }
}

#[test]
fn transform_checks_lengths() {
    let first: Op = serde_json::from_str("[1]").unwrap();
    let second: Op = serde_json::from_str("[2]").unwrap();
    assert_eq!(ot::transform(&first, &second).unwrap_err(), ot::OtError::Length);
}

#[test]
fn deserialising_normalises() {
    let op: Op = serde_json::from_str(r#"[1, 1, -1, "a", "b", -2]"#).unwrap();
    assert_eq!(serde_json::to_value(&op).unwrap(), serde_json::json!([2, "ab", -3]));
    assert_eq!(op.base_len(), 5);
    assert_eq!(op.target_len(), 4);
    assert_eq!(op.inserted_bytes(), 2);
}

#[test]
fn lengths_count_scalar_values() {
    let op: Op = serde_json::from_str(r#"[1, "😀ä", -1]"#).unwrap();
    assert_eq!(op.base_len(), 2);
    assert_eq!(op.target_len(), 3);
    assert_eq!(op.inserted_bytes(), 6);
}

#[test]
fn from_texts_round_trips() {
    for (a, b) in [("", "a"), ("abc", "abc"), ("a😀b", "a😁b"), ("line\n", "")] {
        let op = Op::from_texts(a, b);
        assert_eq!(op.apply(a).unwrap(), b, "{a:?} -> {b:?}");
    }
    let same = serde_json::to_value(Op::from_texts("abc", "abc")).unwrap();
    assert_eq!(same, serde_json::json!([3]));
    let empty = serde_json::to_value(Op::from_texts("", "")).unwrap();
    assert_eq!(empty, serde_json::json!([]));
    let emoji = serde_json::to_value(Op::from_texts("a😀b", "a😁b")).unwrap();
    assert_eq!(emoji, serde_json::json!([1, "😁", -1, 1]));
}

/// What the server tells one client.
enum Down {
    Ack,
    Op(Op),
}

struct Client {
    text: String,
    /// Server operations this client has seen, its own acknowledged ones included.
    revision: usize,
    in_flight: Option<Op>,
    queue: VecDeque<Op>,
    up: VecDeque<(usize, Op)>,
    down: VecDeque<Down>,
}

struct Server {
    text: String,
    history: Vec<Op>,
}

impl Client {
    fn edit(&mut self, rng: &mut StdRng) {
        const ALPHABET: [char; 5] = ['a', 'b', 'ä', '😀', '\n'];
        let mut chars: Vec<char> = self.text.chars().collect();
        let at = rng.random_range(0..=chars.len());
        let deleted = rng.random_range(0..=3).min(chars.len() - at);
        let inserted: Vec<char> =
            (0..rng.random_range(0..=3)).map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())]).collect();
        chars.splice(at..at + deleted, inserted);
        let new: String = chars.into_iter().collect();
        let op = Op::from_texts(&self.text, &new);
        self.text = op.apply(&self.text).unwrap();
        assert_eq!(self.text, new);
        if self.in_flight.is_none() {
            self.up.push_back((self.revision, op.clone()));
            self.in_flight = Some(op);
        } else {
            self.queue.push_back(op);
        }
    }

    fn receive(&mut self) {
        match self.down.pop_front().unwrap() {
            Down::Ack => {
                self.revision += 1;
                self.in_flight = self.queue.pop_front();
                if let Some(op) = &self.in_flight {
                    self.up.push_back((self.revision, op.clone()));
                }
            }
            Down::Op(mut op) => {
                self.revision += 1;
                // The server applied `op` before anything this client still has pending.
                for pending in self.in_flight.iter_mut().chain(self.queue.iter_mut()) {
                    let (op2, pending2) = ot::transform(&op, pending).unwrap();
                    op = op2;
                    *pending = pending2;
                }
                self.text = op.apply(&self.text).unwrap();
            }
        }
    }
}

impl Server {
    fn receive(&mut self, clients: &mut [Client], from: usize) {
        let (revision, mut op) = clients[from].up.pop_front().unwrap();
        for earlier in &self.history[revision..] {
            op = ot::transform(earlier, &op).unwrap().1;
        }
        self.text = op.apply(&self.text).unwrap();
        self.history.push(op.clone());
        for (i, client) in clients.iter_mut().enumerate() {
            client.down.push_back(if i == from { Down::Ack } else { Down::Op(op.clone()) });
        }
    }
}

fn simulate(seed: u64) {
    const CLIENTS: usize = 5;
    const EDITS: usize = 3_000;
    let mut rng = StdRng::seed_from_u64(seed);
    let start = "a😀b\nä".to_owned();
    let mut server = Server { text: start.clone(), history: Vec::new() };
    let mut clients: Vec<Client> = (0..CLIENTS)
        .map(|_| Client {
            text: start.clone(),
            revision: 0,
            in_flight: None,
            queue: VecDeque::new(),
            up: VecDeque::new(),
            down: VecDeque::new(),
        })
        .collect();

    let mut edits = 0;
    loop {
        let pending: Vec<(usize, bool)> = (0..CLIENTS)
            .flat_map(|i| [(i, true), (i, false)])
            .filter(|&(i, up)| if up { !clients[i].up.is_empty() } else { !clients[i].down.is_empty() })
            .collect();
        if edits < EDITS && (pending.is_empty() || rng.random_bool(0.4)) {
            clients[rng.random_range(0..CLIENTS)].edit(&mut rng);
            edits += 1;
        } else if let Some(&(i, up)) = pending.get(rng.random_range(0..pending.len().max(1))) {
            if up {
                server.receive(&mut clients, i);
            } else {
                clients[i].receive();
            }
        } else {
            break;
        }
    }

    assert_eq!(server.history.len(), EDITS, "seed {seed}");
    for (i, client) in clients.iter().enumerate() {
        assert!(client.in_flight.is_none() && client.queue.is_empty());
        assert_eq!(client.text, server.text, "seed {seed}, client {i}");
    }
}

#[test]
fn random_editors_converge() {
    for seed in [1, 2026, 0xB17_7A17] {
        simulate(seed);
    }
}
