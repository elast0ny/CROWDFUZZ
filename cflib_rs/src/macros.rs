

/// This macro is a helper for plugins to register themselves properly
#[macro_export]
macro_rules! register {
    (name, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginName: &'static str = concat!($your_proc, "\0");
    };
    (load, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginLoadCb: cflib::PluginLoadCb = $your_proc;
    };
    (pre_fuzz, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginPreFuzzCb: cflib::PluginPreFuzzCb = $your_proc;
    };
    (fuzz, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginFuzzCb: cflib::PluginFuzzCb = $your_proc;
    };
    (unload, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginUnloadCb: cflib::PluginUnLoadCb = $your_proc;
    };
}