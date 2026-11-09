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
            Self::WrongPassword | Self::Forbidden | Self::UploaderPassword => StatusCode::FORBIDDEN,
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
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        self.log();
        let notice = ErrorNotice { status: self.status(), message: self.to_string() };
        let mut res = (notice.status, notice.message.clone()).into_response();
        res.extensions_mut().insert(notice);
        res
    }
}
