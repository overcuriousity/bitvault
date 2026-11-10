#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::body::Body;
use axum::http::{StatusCode, header};
use bitvault::domain::expiry::Expiry;
use bitvault::domain::paste::{self, NewPaste};
use bitvault::domain::words::PasteId;
use bitvault::domain::{self, Privacy};
use support::{App, app};

async fn create_public(app: &App) -> String {
    let p = NewPaste {
        content: "hello".into(),
        privacy: Privacy::Public,
        expiry: Expiry::Hour24,
        burn_after_reads: 0,
        syntax: None,
        editable: false,
        password: None,
        secret: None,
    };
    paste::create(&app.st, p, None, domain::now()).await.unwrap().words()
}

/// Words no paste in a fresh app has, distinct per `n`.
fn missing(n: u64) -> String {
    PasteId(n).words()
}

async fn get_from(app: &App, uri: &str, ip: &str) -> StatusCode {
    let r = app.req("GET", uri).header("x-forwarded-for", ip).header(header::ACCEPT, "text/html");
    app.send(r.body(Body::empty()).unwrap()).await.status()
}

#[tokio::test]
async fn ten_misses_exhaust_the_lookup_budget_for_that_address_only() {
    let app = app().await;
    let words = create_public(&app).await;
    for n in 0..10 {
        assert_eq!(get_from(&app, &format!("/{}", missing(n)), "203.0.113.1").await, StatusCode::NOT_FOUND);
    }
    assert_eq!(get_from(&app, &format!("/{}", missing(10)), "203.0.113.1").await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(get_from(&app, &format!("/{words}"), "203.0.113.1").await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(get_from(&app, &format!("/{words}"), "203.0.113.2").await, StatusCode::OK);
}

#[tokio::test]
async fn reading_pastes_that_exist_never_spends_the_budget() {
    let app = app().await;
    let words = create_public(&app).await;
    for _ in 0..40 {
        assert_eq!(get_from(&app, &format!("/{words}"), "203.0.113.3").await, StatusCode::OK);
        assert_eq!(get_from(&app, &format!("/{words}/raw"), "203.0.113.3").await, StatusCode::OK);
    }
    assert_eq!(get_from(&app, &format!("/{}", missing(1)), "203.0.113.3").await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn other_not_found_pages_do_not_count() {
    let app = app().await;
    for _ in 0..30 {
        assert_eq!(get_from(&app, "/nope", "203.0.113.4").await, StatusCode::NOT_FOUND);
    }
    assert_eq!(get_from(&app, &format!("/{}", missing(1)), "203.0.113.4").await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_open_form_and_the_api_spend_the_same_budget() {
    let app = app().await;
    for n in 0..5 {
        let form = format!("words={}", missing(n));
        let r = app
            .req("POST", "/open")
            .header("x-forwarded-for", "203.0.113.5")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("hx-request", "true")
            .body(Body::from(form))
            .unwrap();
        assert_eq!(app.send(r).await.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    for n in 5..10 {
        assert_eq!(
            get_from(&app, &format!("/api/v1/pastes/{}", missing(n)), "203.0.113.5").await,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        get_from(&app, &format!("/api/v1/pastes/{}", missing(10)), "203.0.113.5").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn parallel_misses_cannot_outrun_the_budget() {
    let app = std::sync::Arc::new(app().await);
    let start = std::sync::Arc::new(tokio::sync::Barrier::new(25));
    let mut tasks = Vec::new();
    for n in 0..25 {
        let (app, start) = (app.clone(), start.clone());
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            let r = app
                .req("GET", &format!("/{}", missing(n)))
                .header("x-forwarded-for", "203.0.113.6")
                .body(Body::empty())
                .unwrap();
            app.send(r).await.status()
        }));
    }
    let mut misses = 0;
    for t in tasks {
        match t.await.unwrap() {
            StatusCode::NOT_FOUND => misses += 1,
            StatusCode::TOO_MANY_REQUESTS => {}
            other => panic!("unexpected {other}"),
        }
    }
    assert!(misses <= 10, "{misses} misses got through");
}

#[tokio::test]
async fn an_exhausted_budget_renders_a_page_for_browsers_and_json_for_the_api() {
    let app = app().await;
    for n in 0..10 {
        get_from(&app, &format!("/{}", missing(n)), "203.0.113.7").await;
    }
    let r = app.req("GET", &format!("/{}", missing(11))).header("x-forwarded-for", "203.0.113.7");
    let page =
        support::body_text(app.send(r.header(header::ACCEPT, "text/html").body(Body::empty()).unwrap()).await).await;
    assert!(page.contains("<meta name=\"htmx-config\""), "page shell expected");
    let r = app.req("GET", &format!("/api/v1/pastes/{}", missing(11))).header("x-forwarded-for", "203.0.113.7");
    let json = support::body_text(app.send(r.body(Body::empty()).unwrap()).await).await;
    assert!(json.contains("TOO_MANY_ATTEMPTS"), "{json}");
}
