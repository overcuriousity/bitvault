use askama::Template;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::page;
use crate::error::{Error, ErrorNotice};
use crate::state::AppState;

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    heading: &'a str,
    message: &'a str,
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
    let res = next.run(req).await;
    let Some(notice) = res.extensions().get::<ErrorNotice>().cloned() else {
        return res;
    };
    if api {
        return res;
    }
    let page = ErrorPage { heading: heading(notice.status), message: &notice.message }
        .render()
        .map_err(Error::internal)
        .and_then(|body| page(&st, false, "", heading(notice.status), body));
    match page {
        Ok(html) => (notice.status, html).into_response(),
        Err(_) => res,
    }
}

pub async fn not_found() -> Error {
    Error::NotFound
}
