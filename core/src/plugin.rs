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
    init_fn: cflib::PluginInitCbRaw,
    validate_fn: cflib::PluginValidateCbRaw,
    work_fn: cflib::PluginDoWorkCbRaw,
    destroy_fn: cflib::PluginDestroyCbRaw,
}

/// Extracts a function pointer from a module or returns an error if symbol is missing or is null
macro_rules! get_callback_or_ret {
    ($module:ident, $plugin_name:ident, $symbol:expr, $callback_type:ty) => {
        match Plugin::get_impl_ptr::<$callback_type>(&$module, $symbol) {
            Some(f) => {
                if f.is_null() {
                    return Err(From::from(format!(
                        "Symbol '{}' in plugin '{}' does not contain a valid address",
                        $symbol, &$plugin_name
                    )));
                }
                unsafe { *f }
            }
            None => {
                return Err(From::from(format!(
                    "Failed to find symbol '{}' in plugin '{}'",
                    $symbol, &$plugin_name
                )));
            }
        }
    };
}

impl Plugin {
    fn get_impl_ptr<T>(
        module: &libloading::Library,
        symbol_name: &'static str,
    ) -> Option<*const T> {
        unsafe {
            let sym_val = match module.get::<*const T>(symbol_name.as_ref()) {
                Ok(v) => v,
                Err(e) => {
                    warn!("{:?}", e);
                    return None;
                }
            };
            let ptr = sym_val.into_raw();

            //Return the address of the symbol value
            Some(*ptr)
        }
    }

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

        let plugin_name = match Plugin::get_impl_ptr(&module, cflib::_SYMBOL_PLUGIN_NAME_STR) {
            Some(a) => {
                let name_str = unsafe { CStr::from_ptr(*a) };
                String::from(name_str.to_str().unwrap())
            }
            None => {
                debug!(
                    "Plugin did not define name symbol '{}'... using filename as plugin name",
                    cflib::_SYMBOL_PLUGIN_NAME_STR
                );
                String::from(mod_path.file_name().unwrap().to_string_lossy())
            }
        };

        let init_fn = get_callback_or_ret!(
            module,
            plugin_name,
            cflib::_SYMBOL_PLUGIN_INIT_STR,
            cflib::PluginInitCbRaw
        );
        let validate_fn = get_callback_or_ret!(
            module,
            plugin_name,
            cflib::_SYMBOL_PLUGIN_VALIDATE_STR,
            cflib::PluginValidateCbRaw
        );
        let work_fn = get_callback_or_ret!(
            module,
            plugin_name,
            cflib::_SYMBOL_PLUGIN_DOWORK_STR,
            cflib::PluginDoWorkCbRaw
        );
        let destroy_fn = get_callback_or_ret!(
            module,
            plugin_name,
            cflib::_SYMBOL_PLUGIN_DESTROY_STR,
            cflib::PluginDestroyCbRaw
        );

        Ok(Plugin {
            init_called: false,
            has_stats: false,
            priv_data: null_mut(),
            exec_time: unsafe { &mut *null_mut() },
            module,
            name: plugin_name.clone(),
            init_fn,
            validate_fn,
            work_fn,
            destroy_fn,
        })
    }

    pub fn name<'a>(&'a self) -> &'a str {
        return &self.name;
    }

    pub fn init(&mut self, ctx: &mut cflib::CoreInterface) -> Result<()> {
        //Call init at most once
        if self.init_called {
            return Ok(());
        }

        match unsafe { (self.init_fn)(ctx) } {
            cflib::STATUS_SUCCESS => {
                self.init_called = true;
                Ok(())
            }
            e => Err(From::from(format!(
                "'{}'.init() failed with error : {}",
                self.name, e
            ))),
        }
    }

    pub fn validate(&mut self, ctx: &mut cflib::CoreInterface) -> Result<()> {
        if !self.init_called {
            return Err(From::from(format!(
                "Tried to call '{}'.validate() before init()",
                self.name
            )));
        }

        match unsafe { (self.validate_fn)(ctx, self.priv_data) } {
            cflib::STATUS_SUCCESS => Ok(()),
            e => Err(From::from(format!(
                "'{}'.validate() failed with error : {}",
                self.name, e
            ))),
        }
    }

    pub fn do_work(&self, ctx: &mut cflib::CoreInterface) -> Result<()> {
        //No checks for init_called for performance...
        match unsafe { (self.work_fn)(ctx, self.priv_data) } {
            cflib::STATUS_SUCCESS => Ok(()),
            e => Err(From::from(format!(
                "'{}'.work() failed with error : {}",
                self.name, e
            ))),
        }
    }

    pub fn destroy(&self, ctx: &mut cflib::CoreInterface) -> Result<()> {
        //Call init at most once
        if !self.init_called {
            return Err(From::from(format!(
                "Tried to call '{}'.destroy() before init()",
                self.name
            )));
        }

        match unsafe { (self.destroy_fn)(ctx, self.priv_data) } {
            cflib::STATUS_SUCCESS => Ok(()),
            e => Err(From::from(format!(
                "'{}'.destroy() failed with error : {}",
                self.name, e
            ))),
        }
    }
}
