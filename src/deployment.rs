use std::net::IpAddr;

use url::Url;

use crate::config::Config;
use crate::error::Error;

const LOOPBACK_NAMES: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

/// Where the app is served from, derived once from the config.
#[derive(Debug, Clone)]
pub struct Deployment {
    pub origin: String,
    pub secure: bool,
    /// Host of `public_url`, with the port when it is not the scheme's default.
    pub public_host: String,
    /// Host of `short_url`, in the same form.
    pub short_host: Option<String>,
    pub loopback_dev: bool,
    pub port: u16,
    /// `insecure_http`: any well-formed Host is answered, and addresses are built from it when
    /// there is no `public_url`.
    pub plain_http: bool,
    /// Whether `origin` comes from `public_url`, so addresses never follow the request's Host.
    fixed_origin: bool,
    short_origin: Option<String>,
}

fn host_with_port(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    }
}

impl Deployment {
    pub fn from_config(cfg: &Config) -> Result<Self, Error> {
        let (short_host, short_origin) = match cfg.app.short_url.as_deref().map(Url::parse) {
            Some(Ok(u)) => (Some(host_with_port(&u)), Some(u.origin().ascii_serialization())),
            Some(Err(_)) => return Err(Error::Invalid("short_url must be an https URL.".into())),
            None => (None, None),
        };
        let plain_http = cfg.insecure_http;
        let Some(url) = &cfg.public_url else {
            if !cfg.bind.ip().is_loopback() && !plain_http {
                return Err(Error::Invalid(
                    "Set public_url when binding to a non-loopback address, or turn on insecure_http.".into(),
                ));
            }
            let port = cfg.bind.port();
            // Without a public_url, plain HTTP takes its addresses from each request's Host.
            let origin = if plain_http { format!("http://{}", cfg.bind) } else { format!("http://localhost:{port}") };
            return Ok(Self {
                origin,
                secure: false,
                public_host: format!("localhost:{port}"),
                short_host,
                loopback_dev: !plain_http,
                port,
                plain_http,
                fixed_origin: false,
                short_origin,
            });
        };
        let host = url.host_str().unwrap_or_default();
        let is_loopback =
            host == "localhost" || host == "[::1]" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        match url.scheme() {
            "https" => {}
            "http" if is_loopback || plain_http => {}
            _ => {
                return Err(Error::Invalid(
                    "public_url must be https unless it is localhost or insecure_http is on.".into(),
                ));
            }
        }
        Ok(Self {
            origin: url.origin().ascii_serialization(),
            secure: url.scheme() == "https" && !plain_http,
            public_host: host_with_port(url),
            short_host,
            loopback_dev: false,
            port: url.port_or_known_default().unwrap_or(443),
            plain_http,
            fixed_origin: true,
            short_origin,
        })
    }

    /// The origin absolute addresses start with for a request to `host`: `public_url`'s, or
    /// `http://{host}` over plain HTTP without one.
    pub fn base_url(&self, host: &str) -> String {
        if self.plain_http && !self.fixed_origin { format!("http://{host}") } else { self.origin.clone() }
    }

    pub fn host_allowed(&self, host: &str) -> bool {
        if self.short_host.as_deref() == Some(host) {
            return true;
        }
        if self.plain_http {
            return plausible_host(host);
        }
        if self.loopback_dev {
            return LOOPBACK_NAMES
                .iter()
                .any(|n| host == format!("{n}:{}", self.port) || (self.port == 80 && host == *n));
        }
        host == self.public_host
    }

    /// Whether a request to `host` (already passed by [`Self::host_allowed`]) may come from `origin`.
    pub fn origin_allowed(&self, origin: &str, host: &str) -> bool {
        if self.short_origin.as_deref() == Some(origin) {
            return true;
        }
        if self.plain_http {
            return (self.fixed_origin && origin == self.origin) || origin == format!("http://{host}");
        }
        if self.loopback_dev {
            return LOOPBACK_NAMES.iter().any(|n| origin == format!("http://{n}:{}", self.port));
        }
        origin == self.origin
    }
}

/// A host name or address with an optional port and nothing else, so it can go into an address
/// as it is.
fn plausible_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 261
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']'))
}
