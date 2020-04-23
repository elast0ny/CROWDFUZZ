pub mod bindings;
pub use crate::bindings::*;

pub mod stats;
pub use crate::stats::*;

use ::std::os::raw::c_void;

#[macro_export]
macro_rules! register {
    (name, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginName: &'static str = concat!($your_proc, "\0");
    };
    (init, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginInitFnPtr: cflib::PluginInitCb = Some($your_proc);
    };
    (validate, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginValidateFnPtr: cflib::PluginValidateCb = Some($your_proc);
    };
    (work, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginDoWorkFnPtr: cflib::PluginDoWorkCb = Some($your_proc);
    };
    (destroy, $your_proc:expr) => {
        #[no_mangle]
        pub static __PluginDestroyFnPtr: cflib::PluginDestroyCb = Some($your_proc);
    };
}

#[macro_export]
/// Provides a no-op conversion from raw pointers to Rust references for plugin callbacks
/// Examples :
/// ```Rust
/// let core = ctx_unchecked!(core_ptr); // This is always safe
/// // OR
/// let (core, state) = ctx_unchecked!(core_ptr, priv_data, MyStateType); //This variation can lead to segfaults if no priv_data was set
/// ```
macro_rules! ctx_unchecked {
    ($core_ptr:ident) => {
        unsafe { &mut *($core_ptr) }
    };
    ($core_ptr:ident, $priv_ptr:ident, $priv_type:ty) => {
        unsafe { (&mut *($core_ptr), &mut *($priv_ptr as *mut $priv_type)) }
    };
}

#[macro_export]
/// Helper to extract values from the core store
///
/// ```Rust
/// state.exit_status = store_get_ref!(mandatory, CTuple, core, KEY_EXIT_STATUS_STR, 0);
/// state.dir = store_get_ref!(mandatory, str, core, KEY_SOME_PATH_STR, 0);
///
/// if store_get_ref!(optional, CTuple, core, KEY_EXIT_STATUS_STR, 0).is_some() {
///     //....
/// }
/// ```
macro_rules! store_get_ref {
    (mandatory, c_void, $core:ident, $key_str:ident, $index:expr) => {{
        let ptr: *mut std::ffi::c_void =
            ($core as &mut CoreInterface).store_get_mut($key_str, $index);
        if ptr.is_null() {
            ($core as &mut CoreInterface).log(
                cflib::LOGLEVEL_ERROR,
                &format!("Mandatory key \"{}\"[{}] isnt set...", $key_str, $index),
            );
            return cflib::STATUS_PLUGINERROR;
        }
        ptr
    }};
    (mandatory, str, $core:ident, $key_str:ident, $index:expr) => {
        store_get_ref!(mandatory, CTuple, $core, $key_str, $index).as_utf8()
    };
    (mandatory, $key_type:ty, $core:ident, $key_str:ident, $index:expr) => {
        unsafe { &*(store_get_ref!(mandatory, c_void, $core, $key_str, $index) as *mut $key_type) }
    };
    (optional, str, $core:ident, $key_str:ident, $index:expr) => {{
        let ptr: *mut CTuple = ($core as &mut CoreInterface).store_get_mut($key_str, $index);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &(*ptr) }.as_utf8())
        }
    }};
    (optional, $key_type:ty, $core:ident, $key_str:ident, $index:expr) => {{
        let ptr: *mut $key_type = ($core as &mut CoreInterface).store_get_mut($key_str, $index);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*ptr })
        }
    }};
}

impl CVec {
    /// Sets the contents of the CVec to point to the values of the provided Vec
    pub fn update_from_vec<T>(&mut self, src: &Vec<T>) {
        self.length = src.len();

        // If the backing allocation has changed
        if self.data != src.as_ptr() as _ {
            self.data = src.as_ptr() as _;
            self.capacity = src.capacity() as _;
        }
    }
    /// Returns the CVec as a slice of elements
    pub fn as_slice<T>(&self) -> &[T] {
        if self.length == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.data as *const T, self.length) }
    }
}

impl CTuple {
    /// Creates a tuple with a len & pointer to the utf8 bytes
    pub fn from_utf8<S: AsRef<str>>(src: S) -> Self {
        CTuple {
            first: src.as_ref().len(),
            second: src.as_ref().as_ptr() as _,
        }
    }
    /// Intepret the tuple data as a utf8 str
    pub fn as_utf8(&self) -> &str {
        unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                self.second as *const u8,
                self.first,
            ))
        }
    }
}

// TODO : Find a way to generate these unwraped function pointer types with bindgen
pub type PluginInitCbRaw = unsafe extern "C" fn(core_ptr: *mut CoreInterface) -> PluginStatus;
pub type PluginValidateCbRaw = unsafe extern "C" fn(
    core_ptr: *mut CoreInterface,
    priv_data: *mut ::std::os::raw::c_void,
) -> PluginStatus;
pub type PluginDoWorkCbRaw = unsafe extern "C" fn(
    core_ptr: *mut CoreInterface,
    priv_data: *mut ::std::os::raw::c_void,
) -> PluginStatus;
pub type PluginDestroyCbRaw = unsafe extern "C" fn(
    core_ptr: *mut CoreInterface,
    priv_data: *mut ::std::os::raw::c_void,
) -> PluginStatus;

impl CoreInterface {
    pub fn store_push_back<S: AsRef<str>, T>(&self, key: S, data: *mut T) {
        let key = key.as_ref();
        unsafe {
            (self.store_push_back.unwrap())(self.ctx, key.as_ptr() as _, key.len(), data as *mut _);
        }
    }
    pub fn store_push_front<S: AsRef<str>, T>(&self, key: S, data: *mut T) {
        let key = key.as_ref();
        unsafe {
            (self.store_push_front.unwrap())(self.ctx, key.as_ptr() as _, key.len(), data as *mut _);
        }
    }
    pub fn store_pop_back<S: AsRef<str>, T>(&self, key: S) -> *mut T {
        let key = key.as_ref();
        unsafe { (self.store_pop_back.unwrap())(self.ctx, key.as_ptr() as _, key.len()) as *mut T }
    }
    pub fn store_pop_front<S: AsRef<str>, T>(&self, key: S) -> *mut T {
        let key = key.as_ref();
        unsafe { (self.store_pop_front.unwrap())(self.ctx, key.as_ptr() as _, key.len()) as *mut T }
    }
    pub fn store_get_mut<S: AsRef<str>, T>(&self, key: S, index: usize) -> *mut T {
        let key = key.as_ref();
        unsafe { (self.store_get_mut.unwrap())(self.ctx, key.as_ptr() as _, key.len(), index) as *mut T }
    }
    /// Asks the fuzzer core to log a message
    pub fn log<S: AsRef<str>>(&self, log_level: LogLevel, msg: S) {
        let msg = msg.as_ref();
        unsafe {
            (self.log.unwrap())(self.ctx, log_level, msg.as_ptr() as _, msg.len());
        }
    }
    pub fn add_stat<S: AsRef<str>>(
        &self,
        tag: S,
        stat_type: NewStat,
    ) -> Result<*mut c_void, String> {
        let tag = tag.as_ref();
        let ptr = unsafe {
            (self.add_stat.unwrap())(
                self.ctx,
                tag.as_ptr() as _,
                tag.len() as u16,
                stat_type.to_id(),
                stat_type.max_len(),
            )
        };

        if ptr.is_null() {
            Err(String::from("Unable to allocate stat memory..."))
        } else {
            Ok(ptr)
        }
    }
}

pub fn update_average(cur_avg: &mut u64, new_val: u64, val_num: u64) {
    let cur_val = *cur_avg;
    *cur_avg = if cur_val > new_val {
        cur_val - ((cur_val - new_val) / val_num)
    } else {
        cur_val + ((new_val - cur_val) / val_num)
    };
}
