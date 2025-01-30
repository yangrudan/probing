use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use datafusion::config::{ConfigExtension, ExtensionOptions};

use super::error::EngineError;

/// Represents a configuration option for an engine extension.
///
/// # Fields
/// * `key` - The unique identifier for this option
/// * `value` - The current value of the option, if set
/// * `help` - Static help text describing the purpose and usage of this option
pub struct EngineExtensionOption {
    pub key: String,
    pub value: Option<String>,
    pub help: &'static str,
}

/// A trait for engine extensions that can be configured with key-value pairs.
///
/// This trait defines the interface for extensions that can be registered with
/// the [`EngineExtensionManager`] to provide configurable functionality.
///
/// # Required Methods
///
/// * [`name`] - Returns the unique name of this extension
/// * [`set`] - Sets a configuration option value
/// * [`get`] - Retrieves a configuration option value  
/// * [`options`] - Lists all available configuration options
///
/// # Examples
///
/// ```
/// use probing_engine::core::{EngineExtension, EngineExtensionOption};
/// use probing_engine::core::EngineError;
///
/// #[derive(Debug)]
/// struct MyExtension {
///     some_option: String
/// }
///
/// impl EngineExtension for MyExtension {
///     fn name(&self) -> String {
///         "my_extension".to_string()
///     }
///
///     fn set(&mut self, key: &str, value: &str) -> Result<String, EngineError> {
///         match key {
///             "some_option" => {
///                 let old = self.some_option.clone();
///                 self.some_option = value.to_string();
///                 Ok(old)
///             }
///             _ => Err(EngineError::UnsupportedOption(key.to_string()))
///         }
///     }
///
///     fn get(&self, key: &str) -> Result<String, EngineError> {
///         match key {
///             "some_option" => Ok(self.some_option.clone()),
///             _ => Err(EngineError::UnsupportedOption(key.to_string()))
///         }
///     }
///
///     fn options(&self) -> Vec<EngineExtensionOption> {
///         vec![
///             EngineExtensionOption {
///                 key: "some_option".to_string(),
///                 value: Some(self.some_option.clone()),
///                 help: "An example option"
///             }
///         ]
///     }
/// }
/// let mut ext = MyExtension { some_option: "default".to_string() };
/// assert_eq!(ext.name(), "my_extension");
/// assert_eq!(ext.set("some_option", "new").unwrap(), "default");
/// assert_eq!(ext.get("some_option").unwrap(), "new");
/// ```
pub trait EngineExtension: Debug + Send + Sync {
    fn name(&self) -> String;
    fn set(&mut self, key: &str, value: &str) -> Result<String, EngineError> {todo!()}
    fn get(&self, key: &str) -> Result<String, EngineError> {todo!()}
    fn options(&self) -> Vec<EngineExtensionOption> {todo!()}
}

/// Engine extension management module for configurable functionality.
///
/// This module provides a flexible extension system that allows for runtime configuration
/// of engine components through a key-value interface. It consists of three main components:
///
/// - [`EngineExtensionOption`]: Represents a single configuration option with metadata
/// - [`EngineExtension`]: A trait that must be implemented by configurable extensions
/// - [`EngineExtensionManager`]: Manages multiple extensions and their configurations
///
/// The extension system integrates with DataFusion's configuration framework through
/// implementations of [`ConfigExtension`] and [`ExtensionOptions`].
///
/// # Examples
///
/// ```rust
/// use std::sync::{Arc, Mutex};
/// use probing_engine::core::EngineExtensionManager;
/// use probing_engine::core::{EngineExtension, EngineExtensionOption};
/// use probing_engine::core::EngineError;
/// 
/// #[derive(Debug)]
/// struct MyExtension {
///     some_option: String
/// }
/// 
/// impl EngineExtension for MyExtension {
///     fn name(&self) -> String {
///         "my_extension".to_string()
///     }
/// 
///     fn set(&mut self, key: &str, value: &str) -> Result<String, EngineError> {
///         match key {
///             "some_option" => {
///                 let old = self.some_option.clone();
///                 self.some_option = value.to_string();
///                 Ok(old)
///             }
///             _ => Err(EngineError::UnsupportedOption(key.to_string()))
///         }
///     }
///
///     fn get(&self, key: &str) -> Result<String, EngineError> {
///         match key {
///             "some_option" => Ok(self.some_option.clone()),
///             _ => Err(EngineError::UnsupportedOption(key.to_string()))
///         }
///     }
///
///     fn options(&self) -> Vec<EngineExtensionOption> {
///         vec![
///             EngineExtensionOption {
///                 key: "some_option".to_string(),
///                 value: Some(self.some_option.clone()),
///                 help: "An example option"
///             }
///         ]
///     }
/// }
/// 
/// let mut manager = EngineExtensionManager::default();
/// // Register extensions
/// manager.register(Arc::new(Mutex::new(MyExtension { some_option: "default".to_string() })));
///
/// // Configure extensions
/// manager.set_option("some_option", "new").unwrap();
/// assert_eq!(manager.get_option("some_option").unwrap(), "new");
///
/// // List all available options
/// let options = manager.options();
/// ```
#[derive(Debug, Default)]
pub struct EngineExtensionManager {
    extensions: Vec<Arc<Mutex<dyn EngineExtension + Send + Sync>>>,
}

impl EngineExtensionManager {
    pub fn register(&mut self, extension: Arc<Mutex<dyn EngineExtension + Send + Sync>>) {
        self.extensions.push(extension);
    }

    pub fn set_option(&mut self, key: &str, value: &str) -> Result<(), EngineError> {
        for extension in &self.extensions {
            if let Ok(mut ext) = extension.lock() {
                match ext.set(key, value) {
                    Ok(old) => {
                        log::info!("setting update [{}]:{key}={value} <= {old}", ext.name());
                        return Ok(());
                    }
                    Err(EngineError::UnsupportedOption(_)) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Err(EngineError::UnsupportedOption(key.to_string()))
    }

    pub fn get_option(&self, key: &str) -> Result<String, EngineError> {
        for extension in &self.extensions {
            if let Ok(ext) = extension.lock() {
                if let Ok(value) = ext.get(key) {
                    log::info!("setting read [{}]:{key}={value}", ext.name());
                    return Ok(value);
                }
            }
        }
        Err(EngineError::UnsupportedOption(key.to_string()))
    }

    pub fn options(&self) -> Vec<EngineExtensionOption> {
        let mut options = Vec::new();
        for extension in &self.extensions {
            options.extend(extension.lock().unwrap().options());
        }
        options
    }
}

impl ConfigExtension for EngineExtensionManager {
    const PREFIX: &'static str = "probing";
}

impl ExtensionOptions for EngineExtensionManager {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn cloned(&self) -> Box<dyn ExtensionOptions> {
        Box::new(EngineExtensionManager {
            extensions: self.extensions.iter().map(Arc::clone).collect(),
        })
    }

    fn set(&mut self, key: &str, value: &str) -> datafusion::error::Result<()> {
        match self.set_option(key, value) {
            Ok(_) => Ok(()),
            Err(e) => Err(datafusion::error::DataFusionError::Execution(e.to_string())),
        }
    }

    fn entries(&self) -> Vec<datafusion::config::ConfigEntry> {
        self.options()
            .iter()
            .map(|option| datafusion::config::ConfigEntry {
                key: format!("{}.{}", Self::PREFIX, option.key),
                value: option.value.clone(),
                description: option.help,
            })
            .collect()
    }
}
