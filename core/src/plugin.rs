use ::log::*;

use std::ffi::{c_void, CStr};
use std::path::PathBuf;
use std::ptr::null_mut;

use crate::Result;

pub struct Plugin {
    pub init_called: bool,
    pub priv_data: *mut c_void,
    pub has_stats: bool,
    pub exec_time: &'static mut u64,

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
        match unsafe{$module.get::<*const *const $callback_type>($symbol)} {
            Ok(sym) => {
                if sym.is_null() {
                    return Err(From::from(format!(
                        "Symbol {:?} in plugin '{}' does not contain a valid address",
                        unsafe { CStr::from_ptr($symbol.as_ptr()  as *const _) }, &$plugin_name
                    )));
                }
                unsafe { ***sym.into_raw() }
            }
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to find symbol {:?} in plugin '{}' : {}",
                    unsafe { CStr::from_ptr($symbol.as_ptr() as *const _) }, &$plugin_name, e
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
        let rustc_version = match unsafe{module.get::<*const *const i8>(cflib::RUSTC_SYM)} {
            Ok(sym) => {
                let tmp = unsafe { CStr::from_ptr(**sym.into_raw()) };
                String::from(tmp.to_str().unwrap())
            }
            Err(e) => {
                return Err(From::from(format!("Failed to get plugin version for '{}' : {}", mod_path.to_string_lossy(), e)));
            }
        };
        if rustc_version != &cflib::RUSTC_VERSION[.. cflib::RUSTC_VERSION.len()-1] {
            return Err(From::from(format!("Plugin version '{}' for '{}' does not match CROWDFUZZ version : '{}'", rustc_version,  mod_path.to_string_lossy(), &cflib::RUSTC_VERSION[.. cflib::RUSTC_VERSION.len()-1])));
        }
        
        let plugin_name = match unsafe{module.get::<*const *const i8>(cflib::NAME_SYM)} {
            Ok(sym) => {
                let name_str = unsafe { CStr::from_ptr(**sym.into_raw()) };
                String::from(name_str.to_str().unwrap())
            }
            Err(e) => {
                debug!(
                    "Plugin did not define name symbol '{:?}'... using filename as plugin name",
                    cflib::NAME_SYM
                );
                String::from(mod_path.file_name().unwrap().to_string_lossy())
            }
        };

        let load_fn = get_callback_or_ret!(
            module,
            plugin_name,
            cflib::ONLOAD_SYM,
            cflib::PluginLoadCb
        );
        let pre_fuzz_fn = get_callback_or_ret!(
            module,
            plugin_name,
            cflib::PRE_FUZZ_SYM,
            cflib::PluginPreFuzzCb
        );
        let fuzz_fn = get_callback_or_ret!(
            module,
            plugin_name,
            cflib::FUZZ_SYM,
            cflib::PluginFuzzCb
        );
        let unload_fn = get_callback_or_ret!(
            module,
            plugin_name,
            cflib::UNLOAD_SYM,
            cflib::PluginUnLoadCb
        );

        Ok(Plugin {
            init_called: false,
            has_stats: false,
            priv_data: null_mut(),
            exec_time: unsafe { &mut *null_mut() },
            module,
            name: plugin_name.clone(),
            load_fn,
            pre_fuzz_fn,
            fuzz_fn,
            unload_fn,
        })
    }

    pub fn name<'a>(&'a self) -> &'a str {
        return &self.name;
    }

    pub fn init(&mut self, ctx: &dyn cflib::PluginInterface) -> Result<()> {
        //Call init at most once
        if self.init_called {
            return Ok(());
        }

        match unsafe { (self.pre_fuzz_fn)(ctx) } as _ {
            cflib::PluginStatus::Success => {
                self.init_called = true;
                Ok(())
            }
            e => Err(From::from(format!(
                "'{}'.init() failed with error : {:?}",
                self.name, e
            ))),
        }
    }

    pub fn validate(&mut self, ctx: &dyn cflib::PluginInterface) -> Result<()> {
        if !self.init_called {
            return Err(From::from(format!(
                "Tried to call '{}'.validate() before init()",
                self.name
            )));
        }

        match unsafe { (self.pre_fuzz_fn)(ctx) } as _ {
            cflib::PluginStatus::Success => Ok(()),
            e => Err(From::from(format!(
                "'{}'.validate() failed with error : {:?}",
                self.name, e
            ))),
        }
    }

    pub fn do_work(&self, ctx: &dyn cflib::PluginInterface) -> Result<()> {
        //No checks for init_called for performance...
        match unsafe { (self.fuzz_fn)(ctx) } as _ {
            cflib::PluginStatus::Success => Ok(()),
            e => Err(From::from(format!(
                "'{}'.work() failed with error : {:?}",
                self.name, e
            ))),
        }
    }

    pub fn destroy(&self, ctx: &dyn cflib::PluginInterface) -> Result<()> {
        //Call init at most once
        if !self.init_called {
            return Err(From::from(format!(
                "Tried to call '{}'.destroy() before init()",
                self.name
            )));
        }

        match unsafe { (self.unload_fn)(ctx) } as _ {
            cflib::PluginStatus::Success => Ok(()),
            e => Err(From::from(format!(
                "'{}'.destroy() failed with error : {:?}",
                self.name, e
            ))),
        }
    }
}
