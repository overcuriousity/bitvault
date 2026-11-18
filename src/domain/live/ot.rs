//! Text operations: an operation walks the whole text once, keeping, deleting and inserting.
//! Positions and lengths count Unicode scalar values (`char`s), never bytes or UTF-16 units.
//!
//! On the wire an operation is a JSON array: a positive integer keeps that many characters, a
//! negative one deletes them, a string inserts it. `tests/fixtures/ot.json` pins the behaviour
//! that the browser's implementation shares.

use std::fmt;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

/// One step of an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Keep(u32),
    Delete(u32),
    Insert(String),
}

/// A normalised operation: adjacent parts of one kind are merged, no part is empty, and an
/// insert stands before a delete at the same spot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Op {
    parts: Vec<Part>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OtError {
    /// The operation's base length does not match the text, or two operations do not share a
    /// base.
    #[error("The operation does not fit the text's length.")]
    Length,
}

fn char_len(s: &str) -> u32 {
    u32::try_from(s.chars().count()).unwrap_or(u32::MAX)
}

/// Splits `s` after `n` characters, or at its end if it is shorter.
fn split_chars(s: &str, n: u32) -> (&str, &str) {
    let n = usize::try_from(n).unwrap_or(usize::MAX);
    let at = s.char_indices().nth(n).map_or(s.len(), |(i, _)| i);
    s.split_at(at)
}

impl Op {
    /// Builds a normalised operation from parts in any form.
    pub fn from_parts(parts: impl IntoIterator<Item = Part>) -> Self {
        let mut op = Self::default();
        for part in parts {
            op.push(part);
        }
        op
    }

    pub fn parts(&self) -> &[Part] {
        &self.parts
    }

    fn push(&mut self, part: Part) {
        match part {
            Part::Keep(0) | Part::Delete(0) => {}
            Part::Insert(s) if s.is_empty() => {}
            Part::Keep(n) => match self.parts.last_mut() {
                Some(Part::Keep(m)) => *m = m.saturating_add(n),
                _ => self.parts.push(Part::Keep(n)),
            },
            Part::Delete(n) => match self.parts.last_mut() {
                Some(Part::Delete(m)) => *m = m.saturating_add(n),
                _ => self.parts.push(Part::Delete(n)),
            },
            Part::Insert(s) => {
                let at = match self.parts.last() {
                    Some(Part::Delete(_)) => self.parts.len() - 1,
                    _ => self.parts.len(),
                };
                let before = at.checked_sub(1).and_then(|i| self.parts.get_mut(i));
                if let Some(Part::Insert(before)) = before {
                    before.push_str(&s);
                } else {
                    self.parts.insert(at, Part::Insert(s));
                }
            }
        }
    }

    /// The length, in characters, of the text this operation applies to.
    pub fn base_len(&self) -> u32 {
        self.parts.iter().fold(0, |sum, part| match part {
            Part::Keep(n) | Part::Delete(n) => sum.saturating_add(*n),
            Part::Insert(_) => sum,
        })
    }

    /// The length, in characters, of the text this operation produces.
    pub fn target_len(&self) -> u32 {
        self.parts.iter().fold(0, |sum, part| match part {
            Part::Keep(n) => sum.saturating_add(*n),
            Part::Delete(_) => sum,
            Part::Insert(s) => sum.saturating_add(char_len(s)),
        })
    }

    /// The UTF-8 size of everything this operation inserts.
    pub fn inserted_bytes(&self) -> usize {
        self.parts
            .iter()
            .map(|part| match part {
                Part::Insert(s) => s.len(),
                Part::Keep(_) | Part::Delete(_) => 0,
            })
            .sum()
    }

    pub fn apply(&self, text: &str) -> Result<String, OtError> {
        if usize::try_from(self.base_len()) != Ok(text.chars().count()) {
            return Err(OtError::Length);
        }
        let mut out = String::with_capacity(text.len() + self.inserted_bytes());
        let mut rest = text;
        for part in &self.parts {
            match part {
                Part::Keep(n) => {
                    let (kept, tail) = split_chars(rest, *n);
                    out.push_str(kept);
                    rest = tail;
                }
                Part::Delete(n) => rest = split_chars(rest, *n).1,
                Part::Insert(s) => out.push_str(s),
            }
        }
        Ok(out)
    }

    /// The operation that turns `old` into `new`: the common prefix and suffix are kept, the
    /// middle is deleted and the new middle inserted.
    pub fn from_texts(old: &str, new: &str) -> Self {
        let prefix: usize = old.chars().zip(new.chars()).take_while(|(a, b)| a == b).map(|(a, _)| a.len_utf8()).sum();
        let (old_rest, new_rest) = (&old[prefix..], &new[prefix..]);
        let suffix: usize = old_rest
            .chars()
            .rev()
            .zip(new_rest.chars().rev())
            .take_while(|(a, b)| a == b)
            .map(|(a, _)| a.len_utf8())
            .sum();
        let old_middle = &old_rest[..old_rest.len() - suffix];
        let new_middle = &new_rest[..new_rest.len() - suffix];
        Self::from_parts([
            Part::Keep(char_len(&old[..prefix])),
            Part::Delete(char_len(old_middle)),
            Part::Insert(new_middle.to_owned()),
            Part::Keep(char_len(&old_rest[old_middle.len()..])),
        ])
    }
}

/// A part with what is left of it while two operations are walked in step.
#[derive(Clone, Copy)]
enum Step<'a> {
    Keep(u32),
    Delete(u32),
    Insert(&'a str),
}

struct Steps<'a> {
    rest: std::slice::Iter<'a, Part>,
    head: Option<Step<'a>>,
}

impl<'a> Steps<'a> {
    fn new(op: &'a Op) -> Self {
        let mut steps = Self { rest: op.parts.iter(), head: None };
        steps.advance();
        steps
    }

    fn advance(&mut self) {
        self.head = self.rest.next().map(|part| match part {
            Part::Keep(n) => Step::Keep(*n),
            Part::Delete(n) => Step::Delete(*n),
            Part::Insert(s) => Step::Insert(s),
        });
    }

    /// Consumes `n` characters of the current keep or delete.
    fn take(&mut self, n: u32) {
        match &mut self.head {
            Some(Step::Keep(left) | Step::Delete(left)) if *left > n => *left -= n,
            _ => self.advance(),
        }
    }
}

/// Transforms two operations on the same text into `(first', second')`, so that `second'`
/// applies after `first` and `first'` after `second`, both giving the same text. `first` is the
/// operation the server received first: of two inserts at one position, its text comes first.
pub fn transform(first: &Op, second: &Op) -> Result<(Op, Op), OtError> {
    if first.base_len() != second.base_len() {
        return Err(OtError::Length);
    }
    let (mut first2, mut second2) = (Op::default(), Op::default());
    let (mut a, mut b) = (Steps::new(first), Steps::new(second));
    loop {
        match (a.head, b.head) {
            (None, None) => break,
            (Some(Step::Insert(s)), _) => {
                first2.push(Part::Insert(s.to_owned()));
                second2.push(Part::Keep(char_len(s)));
                a.advance();
            }
            (_, Some(Step::Insert(s))) => {
                first2.push(Part::Keep(char_len(s)));
                second2.push(Part::Insert(s.to_owned()));
                b.advance();
            }
            (None, Some(_)) | (Some(_), None) => return Err(OtError::Length),
            (Some(Step::Keep(x)), Some(Step::Keep(y))) => {
                let n = x.min(y);
                first2.push(Part::Keep(n));
                second2.push(Part::Keep(n));
                a.take(n);
                b.take(n);
            }
            (Some(Step::Delete(x)), Some(Step::Delete(y))) => {
                let n = x.min(y);
                a.take(n);
                b.take(n);
            }
            (Some(Step::Delete(x)), Some(Step::Keep(y))) => {
                let n = x.min(y);
                first2.push(Part::Delete(n));
                a.take(n);
                b.take(n);
            }
            (Some(Step::Keep(x)), Some(Step::Delete(y))) => {
                let n = x.min(y);
                second2.push(Part::Delete(n));
                a.take(n);
                b.take(n);
            }
        }
    }
    Ok((first2, second2))
}

impl Serialize for Op {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.parts.len()))?;
        for part in &self.parts {
            match part {
                Part::Keep(n) => seq.serialize_element(n)?,
                Part::Delete(n) => seq.serialize_element(&-i64::from(*n))?,
                Part::Insert(s) => seq.serialize_element(s)?,
            }
        }
        seq.end()
    }
}

/// One element of the wire form.
struct WirePart(Part);

impl<'de> Deserialize<'de> for WirePart {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PartVisitor;

        impl Visitor<'_> for PartVisitor {
            type Value = WirePart;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a non-zero integer or a non-empty string")
            }

            fn visit_u64<E: de::Error>(self, n: u64) -> Result<WirePart, E> {
                match u32::try_from(n) {
                    Ok(0) | Err(_) => Err(E::invalid_value(de::Unexpected::Unsigned(n), &self)),
                    Ok(n) => Ok(WirePart(Part::Keep(n))),
                }
            }

            fn visit_i64<E: de::Error>(self, n: i64) -> Result<WirePart, E> {
                if n >= 0 {
                    return self.visit_u64(n.unsigned_abs());
                }
                u32::try_from(n.unsigned_abs())
                    .map(|n| WirePart(Part::Delete(n)))
                    .map_err(|_| E::invalid_value(de::Unexpected::Signed(n), &self))
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<WirePart, E> {
                if s.is_empty() {
                    return Err(E::invalid_value(de::Unexpected::Str(s), &self));
                }
                Ok(WirePart(Part::Insert(s.to_owned())))
            }
        }

        deserializer.deserialize_any(PartVisitor)
    }
}

impl<'de> Deserialize<'de> for Op {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OpVisitor;

        impl<'de> Visitor<'de> for OpVisitor {
            type Value = Op;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an array of operation parts")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Op, A::Error> {
                let (mut base, mut target) = (0u64, 0u64);
                let mut op = Op::default();
                while let Some(WirePart(part)) = seq.next_element()? {
                    match &part {
                        Part::Keep(n) => {
                            base += u64::from(*n);
                            target += u64::from(*n);
                        }
                        Part::Delete(n) => base += u64::from(*n),
                        Part::Insert(s) => target += s.chars().count() as u64,
                    }
                    if base > u64::from(u32::MAX) || target > u64::from(u32::MAX) {
                        return Err(de::Error::custom("the operation is too long"));
                    }
                    op.push(part);
                }
                Ok(op)
            }
        }

        deserializer.deserialize_seq(OpVisitor)
    }
}
