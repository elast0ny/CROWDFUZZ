use crate::*;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
pub enum PluginStatus {
    Success,
    Error,
}

pub trait PluginInterface {
    /// Logs a message at info level
    fn info(&self, msg: &str);
    /// Logs a message at warn level
    fn warn(&self, msg: &str);
    /// Logs a message at error level
    fn error(&self, msg: &str);
    /// Logs a message at debug level
    fn debug(&self, msg: &str);
    /// Logs a message at trace level
    fn trace(&self, msg: &str);
    /// Adds a statistic in the stats shared memory mapping
    /// This can fail if the mapping runs out of space.
    fn add_stat(&mut self, tag: &str, stat: NewStat) -> Result<StatVal>;
}

/// Initializes the plugin.
/// The plugin should add all of its owned values to the store and
/// return a pointer to its state data if applicable.
pub type PluginLoadCb = fn(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8>;
/// During this callback, the plugin should make sure all the non-owned store
/// values are present for its functionning.
pub type PluginPreFuzzCb =
    fn(core: &mut dyn PluginInterface, store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()>;
/// Perform its task for a single fuzz iteration
pub type PluginFuzzCb =
    fn(core: &mut dyn PluginInterface, store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()>;
/// Unload and free our resources
pub type PluginUnLoadCb =
    fn(core: &mut dyn PluginInterface, store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()>;

pub static RUSTC_VERSION: &str = concat!(env!("RUSTC_VERSION"), "\0"); // To set this, copy cflib/res/build.rs into your crate's root

pub const RUSTC_SYM: &[u8] = b"__RustcVersion\0";
pub const NAME_SYM: &[u8] = b"__PluginName\0";

pub const ONLOAD_SYM: &[u8] = b"__PluginLoadCb\0";
pub const PRE_FUZZ_SYM: &[u8] = b"__PluginPreFuzzCb\0";
pub const FUZZ_SYM: &[u8] = b"__PluginFuzzCb\0";
pub const UNLOAD_SYM: &[u8] = b"__PluginUnloadCb\0";
