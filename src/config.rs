use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

use crate::deployment::Deployment;
use crate::error::Error;

const ENV_PREFIX: &str = "BITVAULT__";

pub const PRIVACY_LEVELS: [&str; 5] = ["public", "unlisted", "readonly", "private", "secret"];
pub const EXPIRY_CHOICES: [&str; 10] =
    ["1min", "10min", "1hour", "24hour", "3days", "1week", "1month", "6months", "1year", "never"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub bind: SocketAddr,
    pub public_url: Option<Url>,
    pub data_dir: Option<PathBuf>,
    pub trusted_proxies: Vec<IpNet>,
    pub app: AppConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            public_url: None,
            data_dir: None,
            trusted_proxies: ["127.0.0.1/32", "::1/128"].iter().filter_map(|s| s.parse().ok()).collect(),
            app: AppConfig::default(),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AppConfig {
    pub title: String,
    pub short_url: Option<String>,
    pub admin_password: Option<String>,
    pub uploader_password: Option<String>,
    pub listing: bool,
    pub editable: bool,
    pub read_stats: bool,
    pub highlight: bool,
    pub qr: bool,
    pub translate_url: Option<String>,
    pub privacy_levels: Vec<String>,
    pub default_privacy: String,
    pub expiry_choices: Vec<String>,
    pub default_expiry: String,
    pub max_expiry: String,
    pub default_burn_after: u32,
    pub max_file_mb: u64,
    pub max_secret_file_mb: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        let strings = |xs: &[&str]| xs.iter().map(|s| (*s).to_owned()).collect();
        Self {
            title: "BitVault".into(),
            short_url: None,
            admin_password: None,
            uploader_password: None,
            listing: true,
            editable: false,
            read_stats: false,
            highlight: true,
            qr: true,
            translate_url: None,
            privacy_levels: strings(&PRIVACY_LEVELS),
            default_privacy: "unlisted".into(),
            expiry_choices: strings(&EXPIRY_CHOICES),
            default_expiry: "24hour".into(),
            max_expiry: "1week".into(),
            default_burn_after: 0,
            max_file_mb: 2048,
            max_secret_file_mb: 256,
        }
    }
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |p: &Option<String>| p.as_ref().map(|_| "***");
        f.debug_struct("AppConfig")
            .field("title", &self.title)
            .field("short_url", &self.short_url)
            .field("admin_password", &redact(&self.admin_password))
            .field("uploader_password", &redact(&self.uploader_password))
            .field("listing", &self.listing)
            .field("editable", &self.editable)
            .field("privacy_levels", &self.privacy_levels)
            .field("expiry_choices", &self.expiry_choices)
            .finish_non_exhaustive()
    }
}

/// Loads the config from an optional TOML file, then `BITVAULT__SECTION__KEY` variables.
/// `BITVAULT__SECTION__KEY_FILE=/path` sets `section.key` to the trimmed contents of that file.
pub fn load(file: Option<&Path>) -> Result<Config, Error> {
    let mut fig = Figment::new();
    if let Some(path) = file {
        if !path.exists() {
            return Err(Error::Invalid(format!("Config file {} does not exist.", path.display())));
        }
        fig = fig.merge(Toml::file(path));
    }
    fig = fig
        .merge(Env::prefixed(ENV_PREFIX).split("__").filter(|k| !k.as_str().to_ascii_lowercase().ends_with("_file")));
    for (key, path) in std::env::vars() {
        let Some(name) = key.strip_prefix(ENV_PREFIX).and_then(|rest| rest.strip_suffix("_FILE")) else {
            continue;
        };
        let secret = std::fs::read_to_string(&path)
            .map_err(|e| Error::Invalid(format!("Cannot read the secret file {path}: {e}.")))?;
        fig = fig.merge((name.to_ascii_lowercase().replace("__", "."), secret.trim().to_owned()));
    }
    fig.extract().map_err(|e| Error::Invalid(format!("Invalid configuration: {e}.")))
}

impl Config {
    /// Stops start-up on a combination that cannot work, naming the key to fix.
    pub fn validate(&self) -> Result<(), Error> {
        let a = &self.app;
        for level in &a.privacy_levels {
            if !PRIVACY_LEVELS.contains(&level.as_str()) {
                return Err(Error::Invalid(format!("privacy_levels has an unknown level '{level}'.")));
            }
        }
        if a.privacy_levels.is_empty() {
            return Err(Error::Invalid("privacy_levels must offer at least one level.".into()));
        }
        if !a.privacy_levels.contains(&a.default_privacy) {
            return Err(Error::Invalid("default_privacy must be one of privacy_levels.".into()));
        }
        for choice in &a.expiry_choices {
            if !EXPIRY_CHOICES.contains(&choice.as_str()) {
                return Err(Error::Invalid(format!("expiry_choices has an unknown choice '{choice}'.")));
            }
        }
        if !a.expiry_choices.contains(&a.default_expiry) {
            return Err(Error::Invalid("default_expiry must be one of expiry_choices.".into()));
        }
        if !a.expiry_choices.contains(&a.max_expiry) {
            return Err(Error::Invalid("max_expiry must be one of expiry_choices.".into()));
        }
        if let Some(raw) = &a.short_url {
            match Url::parse(raw) {
                Ok(u) if u.scheme() == "https" && u.host_str().is_some() => {}
                _ => return Err(Error::Invalid("short_url must be an https URL.".into())),
            }
        }
        if a.max_file_mb == 0 || a.max_secret_file_mb == 0 {
            return Err(Error::Invalid("max_file_mb and max_secret_file_mb must be at least 1.".into()));
        }
        Deployment::from_config(self).map(|_| ())
    }

    pub fn data_dir(&self) -> PathBuf {
        if let Some(d) = &self.data_dir {
            return d.clone();
        }
        if let Some(d) = std::env::var_os("STATE_DIRECTORY") {
            return PathBuf::from(d);
        }
        if let Some(d) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(d).join("bitvault");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local/share/bitvault");
        }
        PathBuf::from("./data")
    }
}
