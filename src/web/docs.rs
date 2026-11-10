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
    text.split("\n\n").map(|p| runs(&p.replace('\n', " "))).filter(|p| !p.is_empty()).collect()
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
    pub fn method_class(&self) -> String {
        self.method.to_ascii_lowercase()
    }

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

const METHODS: [&str; 5] = ["get", "post", "patch", "put", "delete"];
/// Stands for the instance's origin in the stored `curl` lines.
const ORIGIN: &str = "\u{0}origin\u{0}";

impl Reference {
    pub fn from_spec(spec: &Value) -> Self {
        let empty = Map::new();
        let schemas = spec.pointer("/components/schemas").and_then(Value::as_object).unwrap_or(&empty);
        let mut operations = Vec::new();
        for (path, item) in spec.get("paths").and_then(Value::as_object).unwrap_or(&empty) {
            for method in METHODS {
                if let Some(op) = item.get(method) {
                    operations.push(operation(path, method, op, schemas));
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

/// The description, with the example and the minimum where the spec gives them.
fn described(v: &Value) -> Paragraph {
    let mut out = runs(&text_of(v, "description").replace('\n', " "));
    if let Some(example) = v.get("example") {
        let shown = example.as_str().map_or_else(|| example.to_string(), str::to_owned);
        if !out.is_empty() {
            out.push(Run { code: false, text: " ".into() });
        }
        out.push(Run { code: false, text: "Example: ".into() });
        out.push(Run { code: true, text: shown });
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

fn operation(path: &str, method: &str, op: &Value, schemas: &Map<String, Value>) -> Operation {
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
                        description: runs(&text_of(r, "description").replace('\n', " ")),
                        media: content.map(|(m, _)| m.clone()),
                        ty: content.and_then(|(_, c)| c.get("schema")).map(type_ref),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let method_upper = match method {
        "get" => "GET",
        "post" => "POST",
        "patch" => "PATCH",
        "put" => "PUT",
        _ => "DELETE",
    };
    Operation {
        id: text_of(op, "operationId").replace('_', "-"),
        method: method_upper,
        path: path.to_owned(),
        summary: runs(&text_of(op, "summary")),
        description: paragraphs(&text_of(op, "description")),
        examples: examples(method_upper, path, &params, &bodies, schemas, op),
        params,
        bodies,
        answers,
    }
}

/// Example values for path parameters, which the spec does not give.
fn path_value(name: &str) -> &'static str {
    match name {
        "words" => "apple-banana-cherry",
        "position" => "1",
        _ => "1",
    }
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A value for a field in an example body: its example, or a plain one of its type.
fn example_value(name: &str, p: &Value) -> Value {
    if let Some(example) = p.get("example") {
        return example.clone();
    }
    let ty = type_ref(p).text;
    if name == "content" {
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
fn examples(
    method: &str,
    path: &str,
    params: &[Field],
    bodies: &[Body],
    schemas: &Map<String, Value>,
    op: &Value,
) -> Vec<String> {
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
            let schema = op
                .pointer("/requestBody/content")
                .and_then(|c| c.get(&b.media))
                .and_then(|c| c.get("schema"))
                .map(|s| resolve(s, schemas))
                .unwrap_or(&Value::Null);
            let props = schema.get("properties").and_then(Value::as_object);
            // The required fields, or the text when nothing is required.
            let wanted: Vec<&Field> = match b.fields.iter().filter(|f| f.required).collect::<Vec<_>>() {
                some if !some.is_empty() => some,
                _ => b.fields.iter().filter(|f| f.name == "content").collect(),
            };
            let value = |f: &Field| example_value(&f.name, props.and_then(|p| p.get(&f.name)).unwrap_or(&Value::Null));
            if b.media == "multipart/form-data" {
                let mut body: Vec<String> = wanted
                    .iter()
                    .map(|f| {
                        let v = value(f);
                        let shown = v.as_str().map_or_else(|| v.to_string(), str::to_owned);
                        format!("-F {}", quote(&format!("{}={shown}", f.name)))
                    })
                    .collect();
                if b.fields.iter().any(|f| f.name == "file") {
                    body.push(format!("-F {}", quote("file=@notes.txt")));
                }
                line(body)
            } else {
                let object: Map<String, Value> = wanted.iter().map(|f| (f.name.clone(), value(f))).collect();
                let json = Value::Object(object).to_string();
                line(vec![format!("-H {}", quote("Content-Type: application/json")), format!("-d {}", quote(&json))])
            }
        })
        .collect()
}
