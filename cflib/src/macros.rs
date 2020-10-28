/// Macro provided to register a CROWDFUZZ plugin properly.
/// All variants of the macro must be used
///
/// Variants are :
/// register!(name, &str)
/// register!(load, PluginLoadCb)
/// register!(pre_fuzz, PluginPreFuzzCb)
/// register!(fuzz, PluginFuzzCb)
/// register!(unload, PluginUnLoadCb)
#[macro_export]
macro_rules! register {
    (name, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginName: &'static str = concat!($your_proc, "\0");
    };
    (load, $your_proc:expr) => {
        #[no_mangle]
        pub static __RustcVersion: &str = cflib::RUSTC_VERSION;
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

/// Converts a *mut u8 to &mut T
/// # Safety
/// This macro is extremely unsafe. use with caution.
#[macro_export]
macro_rules! box_ref {
    ($var:expr, $typ:ty) => {
        unsafe { Box::leak(box_take!($var, $typ)) }
    };
}

/// Converts a *mut u8 to Box<T>
/// # Safety
/// This macro is extremely unsafe. use with caution.
#[macro_export]
macro_rules! box_take {
    ($var:expr, $typ:ty) => {
        unsafe { Box::from_raw($var as *mut $typ) }
    };
}

