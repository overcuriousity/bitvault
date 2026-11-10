use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Every message is one sentence a person can act on; internal detail is logged, never shown.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Nothing was found at this address. Check the words and try again.")]
    NotFound,
    #[error("Enter the password to open this paste.")]
    PasswordRequired,
    #[error("That password does not open this paste. Check it and try again.")]
    WrongPassword,
    #[error("Too many attempts. Wait a minute and try again.")]
    TooManyAttempts,
    #[error("You do not have access to this.")]
    Forbidden,
    /// A download grant that expired, was voided by a restart, or was never valid.
    #[error("This link has expired. Open the paste again.")]
    GrantExpired,
    /// Forbidden, with the copy that tells an uploader what is missing.
    #[error("Enter the uploader password to create pastes.")]
    UploaderPassword,
    #[error("{0}")]
    Invalid(String),
    #[error("That upload is too large. Remove some files or choose smaller ones.")]
    TooLarge,
    #[error("That format is not supported. Choose a different file.")]
    UnsupportedFormat,
    #[error("No free paste address was found. Try again in a moment.")]
    IdSpaceExhausted,
    #[error("Something went wrong. Try again later.")]
    Db(#[from] sqlx::Error),
    #[error("Something went wrong. Try again later.")]
    Io(#[from] std::io::Error),
    #[error("Something went wrong. Try again later.")]
    Internal(String),
}

impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::PasswordRequired => StatusCode::UNAUTHORIZED,
            Self::WrongPassword | Self::Forbidden | Self::UploaderPassword | Self::GrantExpired => {
                StatusCode::FORBIDDEN
            }
            Self::TooManyAttempts => StatusCode::TOO_MANY_REQUESTS,
            Self::Invalid(_) | Self::UnsupportedFormat => StatusCode::UNPROCESSABLE_ENTITY,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::IdSpaceExhausted => StatusCode::SERVICE_UNAVAILABLE,
            Self::Db(_) | Self::Io(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn internal(e: impl std::fmt::Display) -> Self {
        Self::Internal(e.to_string())
    }

    /// The detail behind an internal error's generic message, for logs and the operator.
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::Db(e) => Some(e.to_string()),
            Self::Io(e) => Some(e.to_string()),
            Self::Internal(d) => Some(d.clone()),
            _ => None,
        }
    }

    /// One line for the operator when start-up fails: the message, with its cause when the
    /// message alone would hide it.
    pub fn startup_message(&self) -> String {
        match self.detail() {
            Some(d) => format!("BitVault could not start: {}.", d.trim_end_matches('.')),
            None => self.to_string(),
        }
    }

    /// Logs the detail of an internal error, which its message never shows.
    pub fn log(&self) {
        match self {
            Self::Db(e) => tracing::error!(detail = %e, "database error"),
            Self::Io(e) => tracing::error!(detail = %e, "io error"),
            Self::Internal(d) => tracing::error!(detail = %d, "internal error"),
            _ => {}
        }
    }
}

/// Carried in the response extensions so the page layer can render `error.html` with the app's own config.
#[derive(Debug, Clone)]
pub struct ErrorNotice {
    pub status: StatusCode,
    pub message: String,
    /// The page should link back to the paste its address names, rather than to the start.
    pub back_to_paste: bool,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        self.log();
        let notice = ErrorNotice {
            status: self.status(),
            message: self.to_string(),
            back_to_paste: matches!(self, Self::GrantExpired),
        };
        let mut res = (notice.status, notice.message.clone()).into_response();
        res.extensions_mut().insert(notice);
        res
    }
}
