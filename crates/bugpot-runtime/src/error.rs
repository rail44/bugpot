//! Crate-wide error type.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Errors emitted by the bugpot runtime.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid image reference {0:?}: {1}")]
    InvalidImageRef(String, String),

    #[error("oci registry error: {0}")]
    Registry(#[from] oci_client::errors::OciDistributionError),

    #[error("failed to deserialize image config: {0}")]
    DeserializeConfig(#[source] serde_json::Error),

    #[error("failed to serialize runtime spec: {0}")]
    SerializeSpec(#[source] serde_json::Error),

    #[error("digest mismatch for layer {digest}")]
    DigestMismatch { digest: String },

    #[error("unsupported layer media type: {0}")]
    UnsupportedMediaType(String),

    #[error("invalid resource spec {field}={value}: {reason}")]
    InvalidResource {
        field: &'static str,
        value: String,
        reason: &'static str,
    },

    #[error("oci-spec error: {0}")]
    OciSpec(#[from] Box<oci_spec::OciSpecError>),

    #[error("libcontainer error: {0}")]
    Libcontainer(#[from] Box<libcontainer::error::LibcontainerError>),

    #[error("app {0:?} not found")]
    AppNotFound(String),

    #[error("app {0:?} already running")]
    AppAlreadyRunning(String),

    #[error("{0}")]
    Other(String),
}

impl RuntimeError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

// Auto-box variants so the `Result` stays small (clippy::result_large_err).
impl From<oci_spec::OciSpecError> for RuntimeError {
    fn from(e: oci_spec::OciSpecError) -> Self {
        Self::OciSpec(Box::new(e))
    }
}

impl From<libcontainer::error::LibcontainerError> for RuntimeError {
    fn from(e: libcontainer::error::LibcontainerError) -> Self {
        Self::Libcontainer(Box::new(e))
    }
}

pub(crate) type Result<T> = std::result::Result<T, RuntimeError>;
