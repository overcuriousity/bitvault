use askama::Template;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::page;
use crate::error::{Error, ErrorNotice};
use crate::state::AppState;

#[derive(Template)]
#[template(path = "notice.html")]
struct NoticeFragment<'a> {
    message: &'a str,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    heading: &'a str,
    message: &'a str,
    /// `/word-word-word` when the page should lead back to that paste.
    paste_href: Option<String>,
}

fn heading(status: StatusCode) -> &'static str {
    match status {
        StatusCode::NOT_FOUND => "Not found",
        StatusCode::UNAUTHORIZED => "Password needed",
        StatusCode::FORBIDDEN => "Not allowed",
        StatusCode::TOO_MANY_REQUESTS => "Too many attempts",
        s if s.is_server_error() => "Something went wrong",
        _ => "That did not work",
    }
}

/// Turns the plain response of an [`Error`] into an `error.html` page inside the shell.
pub async fn render(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let api = req.uri().path().starts_with("/api/");
    let htmx = req.headers().contains_key("hx-request");
    let admin = req.extensions().get::<super::admin::MaybeAdmin>().is_some_and(|a| a.0);
    // Only a well-formed address becomes a link, in its canonical spelling.
    let paste_href = req
        .uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .next()
        .and_then(|w| crate::domain::words::parse(w).ok())
        .map(|id| format!("/{}", id.words()));
    let res = next.run(req).await;
    let Some(notice) = res.extensions().get::<ErrorNotice>().cloned() else {
        return res;
    };
    if api {
        return res;
    }
    if htmx {
        // htmx swaps 422 bodies into the page, so it gets the notice alone, never a document.
        return match (NoticeFragment { message: &super::escape_text(&notice.message) }).render() {
            Ok(html) => (notice.status, axum::response::Html(html)).into_response(),
            Err(_) => res,
        };
    }
    let paste_href = paste_href.filter(|_| notice.back_to_paste);
    let page = ErrorPage { heading: heading(notice.status), message: &notice.message, paste_href }
        .render()
        .map_err(Error::internal)
        .and_then(|body| page(&st, admin, "", heading(notice.status), body));
    match page {
        Ok(html) => (notice.status, html).into_response(),
        Err(_) => res,
    }
}

pub async fn not_found() -> Error {
    Error::NotFound
}
