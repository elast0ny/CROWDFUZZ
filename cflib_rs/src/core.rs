use std::collections::HashMap;
use std::collections::VecDeque;
use crate::*;

#[derive(Debug)]
pub enum PluginStatus {
    Success,
    Error,
}

pub trait PluginInterface {
    fn set_ctx(&mut self, plugin_ctx: *mut u8);
    fn get_ctx(&self) -> *mut u8;
    fn get_store(&mut self) -> &mut HashMap<String, VecDeque<*mut u8>>;
    fn log(&self, level: log::Level, msg: &str);
    fn add_stat(&mut self, stat: NewStat) -> Result<Stat, Box<dyn std::error::Error>>;
}

/// Initializes the plugin
pub type PluginLoadCb = fn(ctx: &dyn PluginInterface) -> PluginStatus;
/// Time to make sure the plugin has everything to fuzz properly
pub type PluginPreFuzzCb = fn(ctx: &dyn PluginInterface) -> PluginStatus;
/// Perform its task for a single fuzz iteration
pub type PluginFuzzCb = fn(ctx: &dyn PluginInterface) -> PluginStatus;
/// Unload and free our resources
pub type PluginUnLoadCb = fn(ctx: &dyn PluginInterface) -> PluginStatus;

#[no_mangle]
pub static RUSTC_VERSION: &'static str = concat!(env!("RUSTC_VERSION"), "\0"); // To set this, copy cflib/res/build.rs into your crate's root

pub const RUSTC_SYM: &[u8] = b"RUSTC_VERSION\0";
pub const NAME_SYM: &[u8] = b"__PluginName\0";

pub const ONLOAD_SYM: &[u8] = b"__PluginLoadCb\0";
pub const PRE_FUZZ_SYM: &[u8] = b"__PluginPreFuzzCb\0";
pub const FUZZ_SYM: &[u8] = b"__PluginFuzzCb\0";
pub const UNLOAD_SYM: &[u8] = b"__PluginUnloadCb\0";