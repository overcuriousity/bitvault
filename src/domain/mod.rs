pub mod admin;
pub mod crypto;
pub mod expiry;
pub mod files;
pub mod grant;
pub mod highlight;
pub mod paste;
pub mod qr;
pub mod words;

/// Who can find and open a paste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privacy {
    Public,
    Unlisted,
    Readonly,
    Private,
    Secret,
}

impl Privacy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Unlisted => "unlisted",
            Self::Readonly => "readonly",
            Self::Private => "private",
            Self::Secret => "secret",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "public" => Self::Public,
            "unlisted" => Self::Unlisted,
            "readonly" => Self::Readonly,
            "private" => Self::Private,
            "secret" => Self::Secret,
            _ => return None,
        })
    }

    /// Only public pastes appear in the list.
    pub fn listed(self) -> bool {
        self == Self::Public
    }

    pub fn needs_password(self) -> bool {
        matches!(self, Self::Readonly | Self::Private | Self::Secret)
    }
}

/// What the paste content is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Url,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Url => "url",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "text" => Some(Self::Text),
            "url" => Some(Self::Url),
            _ => None,
        }
    }
}

/// Current time as Unix seconds (UTC).
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
