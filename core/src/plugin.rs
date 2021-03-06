use ::log::*;

use crate::stats::*;
use crate::Result;
use cflib::*;
use std::ffi::CStr;
use std::path::PathBuf;
use std::ptr::null_mut;

pub struct PluginData {
    name: String,
}
impl PluginData {
    pub fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
        }
    }
}

pub struct PluginCtx<'b> {
    /// Statistic about the fuzzer that live in the shared memory
    pub stats: Stats<'b>,
    /// Data used by the plugins
    pub plugin_data: Vec<PluginData>,
    /// current plugin being executed
    pub cur_plugin_id: usize,
}

impl<'b> PluginInterface for PluginCtx<'b> {
    fn info(&self, msg: &str) {
        let plugin = unsafe { self.plugin_data.get_unchecked(self.cur_plugin_id) };
        info!("[{}] {}", &plugin.name, msg);
    }
    fn warn(&self, msg: &str) {
        let plugin = unsafe { self.plugin_data.get_unchecked(self.cur_plugin_id) };
        warn!("[{}] {}", &plugin.name, msg);
    }
    fn error(&self, msg: &str) {
        let plugin = unsafe { self.plugin_data.get_unchecked(self.cur_plugin_id) };
        error!("[{}] {}", &plugin.name, msg);
    }
    fn debug(&self, msg: &str) {
        let plugin = unsafe { self.plugin_data.get_unchecked(self.cur_plugin_id) };
        debug!("[{}] {}", &plugin.name, msg);
    }
    fn trace(&self, msg: &str) {
        let plugin = unsafe { self.plugin_data.get_unchecked(self.cur_plugin_id) };
        trace!("[{}] {}", &plugin.name, msg);
    }

    /// Creates a new number in the stats memory
    /// This can fail if the mapping runs out of space.
    fn new_stat_num(&mut self, tag: &str, init: u64) -> Result<StatNum> {
        match self.stats.new_stat(tag, NewStat::Num(init)) {
            Ok(StatVal::Num(v)) => Ok(v),
            Err(e) => Err(e),
            _ => unreachable!(),
        }
    }
    /// Creates a new string in the stats memory
    /// This can fail if the mapping runs out of space.
    fn new_stat_str(&mut self, tag: &str, max_size: usize, init_val: &str) -> Result<StatStr> {
        match self
            .stats
            .new_stat(tag, NewStat::Str { max_size, init_val })
        {
            Ok(StatVal::Str(v)) => Ok(v),
            Err(e) => Err(e),
            _ => unreachable!(),
        }
    }
    /// Creates a new byte buffer in the stats memory
    /// This can fail if the mapping runs out of space.
    fn new_stat_bytes(&mut self, tag: &str, max_size: usize, init_val: &[u8]) -> Result<StatBytes> {
        match self
            .stats
            .new_stat(tag, NewStat::Bytes { max_size, init_val })
        {
            Ok(StatVal::Bytes(v)) => Ok(v),
            Err(e) => Err(e),
            _ => unreachable!(),
        }
    }
}

pub struct Plugin {
    pub is_init: bool,
    pub ctx: *mut u8,
    pub has_stats: bool,
    pub exec_time: cflib::StatNum,

    #[allow(dead_code)] // This field is  just to keep the module loaded in memory
    module: libloading::Library,
    name: String,
    load_fn: cflib::PluginLoadCb,
    pre_fuzz_fn: cflib::PluginPreFuzzCb,
    fuzz_fn: cflib::PluginFuzzCb,
    unload_fn: cflib::PluginUnLoadCb,
}

/// Extracts a function pointer from a module or returns an error if symbol is missing or is null
macro_rules! get_callback_or_ret {
    ($module:ident, $plugin_name:ident, $symbol:expr, $callback_type:ty) => {
        match unsafe { $module.get::<*const $callback_type>($symbol) } {
            Ok(sym) => {
                if sym.is_null() {
                    return Err(From::from(format!(
                        "Symbol {:?} in plugin '{}' does not contain a valid address",
                        unsafe { CStr::from_ptr($symbol.as_ptr() as *const _) },
                        &$plugin_name
                    )));
                }
                unsafe { **sym.into_raw() }
            }
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to find symbol {:?} in plugin '{}' : {}",
                    unsafe { CStr::from_ptr($symbol.as_ptr() as *const _) },
                    &$plugin_name,
                    e
                )));
            }
        }
    };
}

impl Plugin {
    pub fn new(mod_path: &PathBuf) -> Result<Plugin> {
        debug!(
            "Loading plugin from file : \"{}\"",
            mod_path.to_string_lossy()
        );
        let module = match libloading::Library::new(mod_path) {
            Ok(m) => m,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to load plugin '{}' : {}",
                    mod_path.to_string_lossy(),
                    e
                )))
            }
        };

        // first check the version to make sure the ABI lines up
        let rustc_version = match unsafe { module.get::<*const *const i8>(cflib::RUSTC_SYM) } {
            Ok(sym) => {
                let tmp = unsafe { CStr::from_ptr(**sym.into_raw()) };
                String::from(tmp.to_str().unwrap())
            }
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to get plugin version for '{}' : {}",
                    mod_path.to_string_lossy(),
                    e
                )));
            }
        };
        if rustc_version != cflib::RUSTC_VERSION[..cflib::RUSTC_VERSION.len() - 1] {
            return Err(From::from(format!(
                "Plugin version '{}' for '{}' does not match CROWDFUZZ version : '{}'",
                rustc_version,
                mod_path.to_string_lossy(),
                &cflib::RUSTC_VERSION[..cflib::RUSTC_VERSION.len() - 1]
            )));
        }

        let plugin_name = match unsafe { module.get::<*const *const i8>(cflib::NAME_SYM) } {
            Ok(sym) => {
                let name_str = unsafe { CStr::from_ptr(**sym.into_raw()) };
                String::from(name_str.to_str().unwrap())
            }
            Err(e) => {
                debug!(
                    "Plugin did not define name symbol '{:?}'... using filename as plugin name : {}",
                    cflib::NAME_SYM, e
                );
                String::from(mod_path.file_name().unwrap().to_string_lossy())
            }
        };

        let load_fn =
            get_callback_or_ret!(module, plugin_name, cflib::ONLOAD_SYM, cflib::PluginLoadCb);
        let pre_fuzz_fn = get_callback_or_ret!(
            module,
            plugin_name,
            cflib::PRE_FUZZ_SYM,
            cflib::PluginPreFuzzCb
        );
        let fuzz_fn =
            get_callback_or_ret!(module, plugin_name, cflib::FUZZ_SYM, cflib::PluginFuzzCb);
        let unload_fn = get_callback_or_ret!(
            module,
            plugin_name,
            cflib::UNLOAD_SYM,
            cflib::PluginUnLoadCb
        );

        #[allow(invalid_value)]
        Ok(Plugin {
            is_init: false,
            has_stats: false,
            ctx: null_mut(),
            exec_time: unsafe { std::mem::MaybeUninit::zeroed().assume_init() },
            module,
            name: plugin_name,
            load_fn,
            pre_fuzz_fn,
            fuzz_fn,
            unload_fn,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn init(
        &mut self,
        interface: &mut dyn cflib::PluginInterface,
        store: &mut CfStore,
    ) -> Result<()> {
        //Call init at most once
        if self.is_init {
            return Ok(());
        }

        let plugin_ctx = match (self.load_fn)(interface, store) {
            Ok(p) => p,
            Err(e) => {
                return Err(From::from(format!(
                    "'{}'.load() failed with error : {}",
                    self.name, e
                )))
            }
        };

        self.ctx = plugin_ctx;
        self.is_init = true;
        Ok(())
    }

    pub fn validate(
        &mut self,
        interface: &mut dyn cflib::PluginInterface,
        store: &mut CfStore,
    ) -> Result<()> {
        if !self.is_init {
            return Err(From::from(format!(
                "Tried to call {}.pre_fuzz() before load()",
                self.name
            )));
        }

        if let Err(e) = (self.pre_fuzz_fn)(interface, store, self.ctx) {
            return Err(From::from(format!("{}.pre_fuzz() : {}", self.name, e)));
        }

        Ok(())
    }

    pub fn do_work(
        &self,
        interface: &mut dyn cflib::PluginInterface,
        store: &mut CfStore,
    ) -> Result<()> {
        //No checks for is_init for performance...

        if let Err(e) = (self.fuzz_fn)(interface, store, self.ctx) {
            return Err(From::from(format!("{}.fuzz() : {}", self.name, e)));
        }

        Ok(())
    }

    pub fn destroy(
        &mut self,
        interface: &mut dyn cflib::PluginInterface,
        store: &mut CfStore,
    ) -> Result<()> {
        //Call init at most once
        if !self.is_init {
            return Err(From::from(format!(
                "Tried to call {}.unload() before load()",
                self.name
            )));
        }

        if let Err(e) = (self.unload_fn)(interface, store, self.ctx) {
            return Err(From::from(format!("{}.unload() : {}", self.name, e)));
        }

        self.ctx = null_mut();
        self.is_init = false;

        Ok(())
    }
}
