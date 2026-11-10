//! `GET /docs`: the API reference, rendered on the server from the same OpenAPI document that
//! `/api/v1/openapi.json` serves. Each call shows its parameters, the fields of its body, its
//! responses and a `curl` line for this instance; the types follow at the end.

use std::sync::OnceLock;

use askama::Template;
use axum::Router;
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use serde_json::{Map, Value};

use super::admin::MaybeAdmin;
use super::{Extras, page_with};
use crate::error::Error;
use crate::security::BaseUrl;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/docs", get(docs))
}

#[derive(Template)]
#[template(path = "docs.html")]
struct Docs<'a> {
    reference: &'a Reference,
    base: &'a str,
    copy_icons: String,
}

async fn docs(State(st): State<AppState>, MaybeAdmin(admin): MaybeAdmin, base: BaseUrl) -> Result<Html<String>, Error> {
    static REFERENCE: OnceLock<Reference> = OnceLock::new();
    let reference = match REFERENCE.get() {
        Some(r) => r,
        None => {
            let spec = serde_json::to_value(crate::api::spec()).map_err(Error::internal)?;
            REFERENCE.get_or_init(|| Reference::from_spec(&spec))
        }
    };
    let page = Docs { reference, base: &base.0, copy_icons: super::copy_icons() };
    let body = page.render().map_err(Error::internal)?;
    page_with(&st, admin, "docs", "API", body, Extras::default())
}

/// Text with `code` spans, as the spec's descriptions write them.
pub struct Run {
    pub code: bool,
    pub text: String,
}

type Paragraph = Vec<Run>;

/// Paragraphs split on blank lines; single line breaks inside one are spaces.
fn paragraphs(text: &str) -> Vec<Paragraph> {
    text.split("\n\n").map(one_line).filter(|p| !p.is_empty()).collect()
}

/// One paragraph: its line breaks are spaces.
fn one_line(text: &str) -> Paragraph {
    runs(&text.replace('\n', " "))
}

fn runs(text: &str) -> Paragraph {
    text.split('`')
        .enumerate()
        .filter(|(_, t)| !t.is_empty())
        .map(|(i, t)| Run { code: i % 2 == 1, text: t.to_owned() })
        .collect()
}

/// A type as shown: its words, and the anchor of the named type it refers to.
pub struct TypeRef {
    pub text: String,
    pub link: Option<String>,
}

pub struct Field {
    pub name: String,
    pub place: Option<String>,
    pub ty: TypeRef,
    pub required: bool,
    pub description: Paragraph,
    /// The spec's example value, for the `curl` lines.
    example: Option<Value>,
}

pub struct Body {
    pub media: String,
    pub ty: TypeRef,
    pub fields: Vec<Field>,
}

pub struct Answer {
    pub status: String,
    pub description: Paragraph,
    pub media: Option<String>,
    pub ty: Option<TypeRef>,
}

pub struct Operation {
    pub id: String,
    pub method: &'static str,
    pub method_class: &'static str,
    pub path: String,
    pub summary: Paragraph,
    pub description: Vec<Paragraph>,
    pub params: Vec<Field>,
    pub bodies: Vec<Body>,
    pub answers: Vec<Answer>,
    /// `curl` lines without the origin, which the page adds for the instance it is served from.
    examples: Vec<String>,
}

impl Operation {
    pub fn examples(&self, base: &str) -> Vec<String> {
        self.examples.iter().map(|e| e.replace(ORIGIN, base)).collect()
    }
}

pub struct Schema {
    pub name: String,
    pub description: Vec<Paragraph>,
    pub ty: TypeRef,
    pub fields: Vec<Field>,
}

pub struct Reference {
    pub intro: Vec<Paragraph>,
    pub operations: Vec<Operation>,
    pub schemas: Vec<Schema>,
}

/// As the spec keys them and as the page shows them.
const METHODS: [(&str, &str); 5] =
    [("get", "GET"), ("post", "POST"), ("patch", "PATCH"), ("put", "PUT"), ("delete", "DELETE")];
/// Stands for the instance's origin in the stored `curl` lines.
const ORIGIN: &str = "\u{0}origin\u{0}";

impl Reference {
    pub fn from_spec(spec: &Value) -> Self {
        let empty = Map::new();
        let schemas = spec.pointer("/components/schemas").and_then(Value::as_object).unwrap_or(&empty);
        let mut operations = Vec::new();
        for (path, item) in spec.get("paths").and_then(Value::as_object).unwrap_or(&empty) {
            for (key, method) in METHODS {
                if let Some(op) = item.get(key) {
                    operations.push(operation(path, key, method, op, schemas));
                }
            }
        }
        Reference {
            intro: paragraphs(spec.pointer("/info/description").and_then(Value::as_str).unwrap_or_default()),
            operations,
            schemas: schemas.iter().map(|(name, s)| schema(name, s, schemas)).collect(),
        }
    }
}

fn text_of(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or_default().to_owned()
}

fn ref_name(v: &Value) -> Option<&str> {
    v.get("$ref").and_then(Value::as_str).and_then(|r| r.rsplit('/').next())
}

/// The named schema `v` refers to, or `v` itself.
fn resolve<'a>(v: &'a Value, schemas: &'a Map<String, Value>) -> &'a Value {
    ref_name(v).and_then(|n| schemas.get(n)).unwrap_or(v)
}

fn type_ref(v: &Value) -> TypeRef {
    if let Some(name) = ref_name(v) {
        return TypeRef { text: name.to_owned(), link: Some(format!("type-{name}")) };
    }
    let types: Vec<&str> = match v.get("type") {
        Some(Value::String(t)) => vec![t.as_str()],
        Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).filter(|t| *t != "null").collect(),
        _ => vec![],
    };
    if types == ["array"] {
        let inner = v.get("items").map(type_ref).unwrap_or(TypeRef { text: "any".into(), link: None });
        return TypeRef { text: format!("array of {}", inner.text), link: inner.link };
    }
    let mut text = if types.is_empty() { "any".to_owned() } else { types.join(" or ") };
    if let Some(media) = v.get("contentMediaType").and_then(Value::as_str) {
        text = format!("bytes ({media})");
    } else if let Some(format) = v.get("format").and_then(Value::as_str) {
        text = format!("{text} ({format})");
    }
    TypeRef { text, link: None }
}

/// A value as text: a string without its quotes, anything else as JSON.
fn shown(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

/// The description, with the example where the spec gives one.
fn described(v: &Value) -> Paragraph {
    let mut out = one_line(&text_of(v, "description"));
    if let Some(example) = v.get("example") {
        if !out.is_empty() {
            out.push(Run { code: false, text: " ".into() });
        }
        out.push(Run { code: false, text: "Example: ".into() });
        out.push(Run { code: true, text: shown(example) });
    }
    out
}

fn fields(v: &Value, schemas: &Map<String, Value>) -> Vec<Field> {
    let v = resolve(v, schemas);
    let required: Vec<&str> = v
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let Some(props) = v.get("properties").and_then(Value::as_object) else { return Vec::new() };
    props
        .iter()
        .map(|(name, p)| Field {
            name: name.clone(),
            place: None,
            ty: type_ref(p),
            required: required.contains(&name.as_str()),
            description: described(p),
            example: p.get("example").cloned(),
        })
        .collect()
}

fn schema(name: &str, v: &Value, schemas: &Map<String, Value>) -> Schema {
    Schema {
        name: name.to_owned(),
        description: paragraphs(&text_of(v, "description")),
        ty: type_ref(v),
        fields: fields(v, schemas),
    }
}

fn operation(
    path: &str,
    method_class: &'static str,
    method: &'static str,
    op: &Value,
    schemas: &Map<String, Value>,
) -> Operation {
    let params: Vec<Field> = op
        .get("parameters")
        .and_then(Value::as_array)
        .map(|ps| {
            ps.iter()
                .map(|p| Field {
                    name: text_of(p, "name"),
                    place: Some(text_of(p, "in")),
                    ty: p.get("schema").map(type_ref).unwrap_or(TypeRef { text: "string".into(), link: None }),
                    required: p.get("required").and_then(Value::as_bool).unwrap_or(false),
                    description: described(p),
                    example: p.get("example").cloned(),
                })
                .collect()
        })
        .unwrap_or_default();
    let bodies: Vec<Body> = op
        .pointer("/requestBody/content")
        .and_then(Value::as_object)
        .map(|content| {
            content
                .iter()
                .map(|(media, c)| {
                    let s = c.get("schema").unwrap_or(&Value::Null);
                    Body { media: media.clone(), ty: type_ref(s), fields: fields(s, schemas) }
                })
                .collect()
        })
        .unwrap_or_default();
    let answers = op
        .get("responses")
        .and_then(Value::as_object)
        .map(|rs| {
            rs.iter()
                .map(|(status, r)| {
                    let content = r.get("content").and_then(Value::as_object).and_then(|c| c.iter().next());
                    Answer {
                        status: status.clone(),
                        description: one_line(&text_of(r, "description")),
                        media: content.map(|(m, _)| m.clone()),
                        ty: content.and_then(|(_, c)| c.get("schema")).map(type_ref),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Operation {
        id: text_of(op, "operationId").replace('_', "-"),
        method,
        method_class,
        path: path.to_owned(),
        summary: runs(&text_of(op, "summary")),
        description: paragraphs(&text_of(op, "description")),
        examples: examples(method, path, &params, &bodies),
        params,
        bodies,
        answers,
    }
}

/// Example values for path parameters, which the spec does not give.
fn path_value(name: &str) -> &'static str {
    if name == "words" { "apple-banana-cherry" } else { "1" }
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A value for a field in an example body: its example, or a plain one of its type.
fn example_value(f: &Field) -> Value {
    if let Some(example) = &f.example {
        return example.clone();
    }
    let ty = &f.ty.text;
    if f.name == "content" {
        Value::String("Hello from curl".into())
    } else if ty.starts_with("integer") {
        Value::from(1)
    } else if ty.starts_with("boolean") {
        Value::Bool(true)
    } else {
        Value::String("…".into())
    }
}

/// One `curl` line per request body type (or one without a body): required parameters and
/// fields only, the rest is in the tables.
fn examples(method: &str, path: &str, params: &[Field], bodies: &[Body]) -> Vec<String> {
    let mut url = format!("{ORIGIN}{path}");
    for p in params.iter().filter(|p| p.place.as_deref() == Some("path")) {
        url = url.replace(&format!("{{{}}}", p.name), path_value(&p.name));
    }
    let headers: Vec<String> = params
        .iter()
        .filter(|p| p.required && p.place.as_deref() == Some("header"))
        .map(|p| format!("-H {}", quote(&format!("{}: …", p.name))))
        .collect();
    let line = |body: Vec<String>| {
        let mut parts = vec!["curl -sS".to_owned()];
        if !matches!(method, "GET" | "POST") || (method == "POST" && body.is_empty()) {
            parts[0].push_str(&format!(" -X {method}"));
        }
        parts.extend(headers.iter().cloned());
        parts.extend(body);
        parts.push(quote(&url));
        // A command with nothing but its address fits on one line.
        if parts.len() <= 2 { parts.join(" ") } else { parts.join(" \\\n  ") }
    };
    if bodies.is_empty() {
        return vec![line(Vec::new())];
    }
    bodies
        .iter()
        .map(|b| {
            // The required fields, or the text when nothing is required.
            let wanted: Vec<&Field> = match b.fields.iter().filter(|f| f.required).collect::<Vec<_>>() {
                some if !some.is_empty() => some,
                _ => b.fields.iter().filter(|f| f.name == "content").collect(),
            };
            if b.media == "multipart/form-data" {
                let mut body: Vec<String> = wanted
                    .iter()
                    .map(|f| format!("-F {}", quote(&format!("{}={}", f.name, shown(&example_value(f))))))
                    .collect();
                if b.fields.iter().any(|f| f.name == "file") {
                    body.push(format!("-F {}", quote("file=@notes.txt")));
                }
                line(body)
            } else {
                let object: Map<String, Value> = wanted.iter().map(|f| (f.name.clone(), example_value(f))).collect();
                let json = Value::Object(object).to_string();
                line(vec![format!("-H {}", quote("Content-Type: application/json")), format!("-d {}", quote(&json))])
            }
        })
        .collect()
}
