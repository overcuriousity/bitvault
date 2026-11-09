//! How long a paste lives. A month is 30 days and a year 365 days.

use crate::config::AppConfig;

const MINUTE: i64 = 60;
const HOUR: i64 = 60 * MINUTE;
const DAY: i64 = 24 * HOUR;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    Min1,
    Min10,
    Hour1,
    Hour24,
    Days3,
    Week1,
    Month1,
    Months6,
    Year1,
    Never,
}

impl Expiry {
    pub const ALL: [Self; 10] = [
        Self::Min1,
        Self::Min10,
        Self::Hour1,
        Self::Hour24,
        Self::Days3,
        Self::Week1,
        Self::Month1,
        Self::Months6,
        Self::Year1,
        Self::Never,
    ];

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Min1 => "1min",
            Self::Min10 => "10min",
            Self::Hour1 => "1hour",
            Self::Hour24 => "24hour",
            Self::Days3 => "3days",
            Self::Week1 => "1week",
            Self::Month1 => "1month",
            Self::Months6 => "6months",
            Self::Year1 => "1year",
            Self::Never => "never",
        }
    }

    /// A phrase for messages, such as "1 week".
    pub fn label(self) -> &'static str {
        match self {
            Self::Min1 => "1 minute",
            Self::Min10 => "10 minutes",
            Self::Hour1 => "1 hour",
            Self::Hour24 => "24 hours",
            Self::Days3 => "3 days",
            Self::Week1 => "1 week",
            Self::Month1 => "1 month",
            Self::Months6 => "6 months",
            Self::Year1 => "1 year",
            Self::Never => "never",
        }
    }

    /// The lifetime in seconds; `None` never expires.
    pub fn seconds(self) -> Option<i64> {
        Some(match self {
            Self::Min1 => MINUTE,
            Self::Min10 => 10 * MINUTE,
            Self::Hour1 => HOUR,
            Self::Hour24 => DAY,
            Self::Days3 => 3 * DAY,
            Self::Week1 => 7 * DAY,
            Self::Month1 => 30 * DAY,
            Self::Months6 => 180 * DAY,
            Self::Year1 => 365 * DAY,
            Self::Never => return None,
        })
    }
}

/// The configured maximum; a value config validation would refuse falls back to the default, 1 week.
pub fn max(cfg: &AppConfig) -> Expiry {
    Expiry::parse(&cfg.max_expiry).unwrap_or(Expiry::Week1)
}

/// Whether `e` is no longer than `max_expiry`; everything is within a maximum of never.
pub fn within_max(cfg: &AppConfig, e: Expiry) -> bool {
    match (e.seconds(), max(cfg).seconds()) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(s), Some(m)) => s <= m,
    }
}

/// Whether `e` is offered in `expiry_choices` and no longer than `max_expiry`.
pub fn allowed(cfg: &AppConfig, e: Expiry) -> bool {
    cfg.expiry_choices.iter().any(|c| c == e.as_str()) && within_max(cfg, e)
}
