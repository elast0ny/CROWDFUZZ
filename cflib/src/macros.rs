

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

/// Creates a Box<T> and leaks the resource as *mut u8
#[macro_export]
macro_rules! box_leak {
    ($var:expr) => {
        Box::into_raw(Box::new($var)) as *mut u8
    };
}

/// Takes a references from a raw pointer to a Box<T> returning &mut T
#[macro_export]
macro_rules! box_ref {
    ($raw_ptr:expr, $typ:ty) => {
        unsafe {Box::leak(Box::from_raw($raw_ptr as *mut $typ))}
    };
}

/// Takes ownership of a raw pointer to a Box<T> returning a Box<T>
#[macro_export]
macro_rules! box_take {
    ($raw_ptr:expr, $typ:ty) => {
        unsafe {Box::from_raw($raw_ptr as *mut $typ)}
    };
}
