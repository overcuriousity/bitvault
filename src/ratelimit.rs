use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{FromFnLayer, Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};

use crate::error::Error;
use crate::security::ClientIp;

const IDLE: Duration = Duration::from_secs(600);
const PRUNE_ABOVE: usize = 1024;
const PRUNE_EVERY: Duration = Duration::from_secs(60);

struct Buckets {
    map: HashMap<IpAddr, (f64, Instant)>,
    last_prune: Instant,
}

/// A per-address token bucket: `per_minute` tokens refill continuously, up to `burst`.
pub struct RateLimiter {
    per_second: f64,
    burst: f64,
    buckets: Mutex<Buckets>,
}

impl RateLimiter {
    pub fn new(per_minute: u32, burst: u32) -> Self {
        Self {
            per_second: f64::from(per_minute) / 60.0,
            burst: f64::from(burst),
            buckets: Mutex::new(Buckets { map: HashMap::new(), last_prune: Instant::now() }),
        }
    }

    /// A poisoned lock only means another request panicked; the counters are still usable.
    fn lock(&self) -> MutexGuard<'_, Buckets> {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Refills the address's bucket and runs `f` on its token count.
    fn with_tokens<T>(&self, ip: IpAddr, f: impl FnOnce(&mut f64) -> T) -> T {
        let now = Instant::now();
        let mut b = self.lock();
        if b.map.len() > PRUNE_ABOVE && now.duration_since(b.last_prune) >= PRUNE_EVERY {
            b.map.retain(|_, (_, seen)| now.duration_since(*seen) <= IDLE);
            b.last_prune = now;
        }
        let (tokens, seen) = b.map.entry(ip).or_insert((self.burst, now));
        *tokens = (*tokens + now.duration_since(*seen).as_secs_f64() * self.per_second).min(self.burst);
        *seen = now;
        f(tokens)
    }

    /// Refuses when the bucket is empty, without consuming a token.
    pub fn check(&self, ip: IpAddr) -> Result<(), Error> {
        self.with_tokens(ip, |t| if *t >= 1.0 { Ok(()) } else { Err(Error::TooManyAttempts) })
    }

    /// Consumes one token, or refuses when the bucket is empty.
    pub fn take(&self, ip: IpAddr) -> Result<(), Error> {
        self.with_tokens(ip, |t| {
            if *t >= 1.0 {
                *t -= 1.0;
                Ok(())
            } else {
                Err(Error::TooManyAttempts)
            }
        })
    }

    /// Records a failed attempt: consumes one token even when none is left.
    pub fn fail(&self, ip: IpAddr) {
        self.with_tokens(ip, |t| *t = (*t - 1.0).max(0.0));
    }
}

async fn limit(State(limiter): State<Arc<RateLimiter>>, req: Request, next: Next) -> Response {
    // Without a ClientIp the security layer is absent, which only happens outside the app; do not block then.
    if let Some(ClientIp(ip)) = req.extensions().get::<ClientIp>().copied()
        && limiter.take(ip).is_err()
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Too many requests. Wait a minute and try again.").into_response();
    }
    next.run(req).await
}

type Layer = FromFnLayer<
    fn(State<Arc<RateLimiter>>, Request, Next) -> std::pin::Pin<Box<dyn Future<Output = Response> + Send>>,
    Arc<RateLimiter>,
    (State<Arc<RateLimiter>>, Request),
>;

/// Answers 429 once the caller's address has used up the limiter's tokens.
pub fn layer(limiter: Arc<RateLimiter>) -> Layer {
    from_fn_with_state(limiter, |s, r, n| Box::pin(limit(s, r, n)))
}
