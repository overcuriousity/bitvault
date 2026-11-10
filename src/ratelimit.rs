use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
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

/// A per-address token bucket: `per_minute` tokens refill continuously, up to `burst`. IPv6
/// clients are keyed by their /64, the smallest block one subscriber usually holds; IPv4 (also
/// when mapped into IPv6) by the address itself.
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
        let ip = bucket_key(ip);
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

    /// Consumes one token, or refuses when the bucket is empty. Failed-attempt callers take a
    /// token before checking a password, so parallel guesses cannot outrun the limit, and
    /// [`refund`](Self::refund) it when the password was right.
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

    /// Gives back a token taken by [`take`](Self::take), never above the burst.
    pub fn refund(&self, ip: IpAddr) {
        let burst = self.burst;
        self.with_tokens(ip, |t| *t = (*t + 1.0).min(burst));
    }
}

/// The bucket an address counts against: an IPv6 address's /64, any other address itself.
pub fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & !u128::from(u64::MAX))),
        },
        v4 @ IpAddr::V4(_) => v4,
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
