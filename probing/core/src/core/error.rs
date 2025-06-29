//! Error handling for the Probing engine
//!
//! This module provides a comprehensive error handling system for the Probing engine.
//! It defines a structured error type hierarchy and conversion capabilities from common
//! external error types.

use thiserror::Error;

/// Core result type for all Probing engine operations
pub type Result<T> = std::result::Result<T, EngineError>;

/// Comprehensive error type for the Probing engine
///
/// Categorizes errors into logical groups to help with error handling and reporting.
#[derive(Error, Debug)]
pub enum EngineError {
    // ===== Plugin System Errors =====
    /// Generic plugin error
    #[error("Plugin error: {0}")]
    PluginError(String),

    /// Plugin not found error
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    /// Plugin registration failure
    #[error("Plugin registration failed: {0}")]
    PluginRegistrationFailed(String),

    // ===== Query Processing Errors =====
    /// General query execution error
    #[error("Query execution error: {0}")]
    QueryError(String),

    /// Internal engine error
    #[error("Internal engine error: {0}")]
    InternalError(String),

    /// Error during external API call
    #[error("API call error: {0}")]
    CallError(String),

    /// Unsupported API call
    #[error("Unsupported API call")]
    UnsupportedCall,

    // ===== Data Processing Errors =====
    /// Apache Arrow data processing error
    #[error("Arrow data error: {0}")]
    ArrowError(#[from] arrow::error::ArrowError),

    /// DataFusion query processing error
    #[error("DataFusion error: {0}")]
    DataFusionError(#[from] datafusion::error::DataFusionError),

    // ===== Business Logic Errors =====
    /// Cluster management error
    #[error("Cluster error: {0}")]
    ClusterError(String),

    // ===== System Errors =====
    /// Thread/mutex concurrency error
    #[error("Concurrency error: {0}")]
    ConcurrencyError(String),

    // ===== Configuration Errors =====
    /// General configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Unsupported configuration option
    #[error("Unsupported option: {0}")]
    UnsupportedOption(String),

    /// Invalid configuration option value
    #[error("Invalid option value: {0}={1}")]
    InvalidOptionValue(String, String),

    /// Attempt to modify read-only option
    #[error("Read-only option: {0}")]
    ReadOnlyOption(String),

    /// Engine not initialized error
    #[error("Engine not initialized")]
    EngineNotInitialized,
}

impl EngineError {
    pub fn with_context<C: Into<String>>(self, context: C) -> EngineError {
        let context = context.into();

        // Helper macro to reduce boilerplate for string-based variants
        macro_rules! add_context {
            ($variant:path, $msg:expr) => {
                $variant(format!("{}: {}", context, $msg))
            };
        }

        match self {
            // String-based error variants that can have context added
            EngineError::PluginError(msg) => add_context!(EngineError::PluginError, msg),
            EngineError::PluginNotFound(msg) => add_context!(EngineError::PluginNotFound, msg),
            EngineError::PluginRegistrationFailed(msg) => {
                add_context!(EngineError::PluginRegistrationFailed, msg)
            }
            EngineError::QueryError(msg) => add_context!(EngineError::QueryError, msg),
            EngineError::InternalError(msg) => add_context!(EngineError::InternalError, msg),
            EngineError::CallError(msg) => add_context!(EngineError::CallError, msg),
            EngineError::ClusterError(msg) => add_context!(EngineError::ClusterError, msg),
            EngineError::ConcurrencyError(msg) => add_context!(EngineError::ConcurrencyError, msg),
            EngineError::ConfigError(msg) => add_context!(EngineError::ConfigError, msg),
            EngineError::UnsupportedOption(msg) => {
                add_context!(EngineError::UnsupportedOption, msg)
            }
            EngineError::ReadOnlyOption(msg) => add_context!(EngineError::ReadOnlyOption, msg),

            // Error variants that cannot or should not have context added
            e @ (EngineError::UnsupportedCall
            | EngineError::ArrowError(_)
            | EngineError::DataFusionError(_)
            | EngineError::InvalidOptionValue(_, _)
            | EngineError::EngineNotInitialized) => e,
        }
    }
}

// Generic lock poison error conversion
impl<T> From<std::sync::PoisonError<T>> for EngineError {
    fn from(err: std::sync::PoisonError<T>) -> Self {
        EngineError::ConcurrencyError(format!("Lock poisoned: {err}"))
    }
}

// String conversion for simple error creation
impl From<String> for EngineError {
    fn from(message: String) -> Self {
        EngineError::InternalError(message)
    }
}

impl From<&str> for EngineError {
    fn from(message: &str) -> Self {
        EngineError::InternalError(message.to_string())
    }
}

#[allow(unused)]
pub trait ResultExt<T> {
    fn context<C: Into<String>>(self, context: C) -> Result<T>;
}

impl<T, E: Into<EngineError>> ResultExt<T> for std::result::Result<T, E> {
    fn context<C: Into<String>>(self, context: C) -> Result<T> {
        self.map_err(|e| {
            let err = e.into();
            err.with_context(context.into())
        })
    }
}

#[allow(unused)]
pub fn ensure(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(EngineError::InternalError(message.into()))
    }
}

#[allow(unused)]
pub fn bail<T>(message: impl Into<String>) -> Result<T> {
    Err(EngineError::InternalError(message.into()))
}
