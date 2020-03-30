pub mod bindings;
pub use crate::bindings::*;

use ::std::mem::{size_of};
use ::std::os::raw::c_void;

#[macro_export]
macro_rules! register {
    (name, $your_proc:expr) => {
        #[no_mangle] pub static __PluginName: &'static str = concat!($your_proc, "\0");
    };
    (init, $your_proc:expr) => {
        #[no_mangle] pub static __PluginInitFnPtr: cflib::PluginInitCb = Some($your_proc);
    };
    (validate, $your_proc:expr) => {
        #[no_mangle] pub static __PluginValidateFnPtr: cflib::PluginValidateCb = Some($your_proc);
    };
    (work, $your_proc:expr) => {
        #[no_mangle] pub static __PluginDoWorkFnPtr: cflib::PluginDoWorkCb = Some($your_proc);
    };
    (destroy, $your_proc:expr) => {
        #[no_mangle] pub static __PluginDestroyFnPtr: cflib::PluginDestroyCb = Some($your_proc);
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
    (mandatory, c_void, $core:ident, $key_str:ident, $index:expr) => {
        {
            let ptr: *mut std::ffi::c_void = ($core as &mut CoreInterface).store_get_mut($key_str, $index);
            if ptr.is_null() {
                ($core as &mut CoreInterface).log(cflib::LOGLEVEL_ERROR, &format!("Mandatory key \"{}\"[{}] isnt set...", $key_str, $index));
                return cflib::STATUS_PLUGINERROR;
            }
            ptr
        }
    };
    (mandatory, str, $core:ident, $key_str:ident, $index:expr) => {
            store_get_ref!(mandatory, CTuple, $core, $key_str, $index).as_utf8()
    };
    (mandatory, $key_type:ty, $core:ident, $key_str:ident, $index:expr) => {
        unsafe{&*(store_get_ref!(mandatory, c_void, $core, $key_str, $index) as *mut $key_type)}
    };
    (optional, str, $core:ident, $key_str:ident, $index:expr) => {
        {
            let ptr: *mut CTuple = ($core as &mut CoreInterface).store_get_mut($key_str, $index);
            if ptr.is_null() {
                None
            } else {
                Some(unsafe{&(*ptr)}.as_utf8())
            }
        }
    };
    (optional, $key_type:ty, $core:ident, $key_str:ident, $index:expr) => {
        {
            let ptr: *mut $key_type = ($core as &mut CoreInterface).store_get_mut($key_str, $index);
            if ptr.is_null() {
                None
            } else {
                Some(unsafe{&*ptr})
            }
        }
    };
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
        unsafe {
            std::slice::from_raw_parts(self.data as *const T, self.length)
        }
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
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(self.second as *const u8, self.first))
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

pub fn stat_header_size(some_val: StatType) -> u16 {
    return match some_val {
        STAT_BYTES | STAT_STR => size_of::<StatHeaderDyn>(),
        _ => size_of::<StatHeader>(),
    } as u16;
}


pub fn stat_static_data_len(some_val: StatType) -> Option<u16> {
    match some_val {
        crate::STAT_NEWCOMPONENT => Some(0),
        crate::STAT_BYTES => None,
        crate::STAT_STR => None, 
        crate::STAT_USIZE => Some(size_of::<usize>() as u16),
        crate::STAT_ISIZE => Some(size_of::<isize>() as u16),
        crate::STAT_U8 => Some(size_of::<u8>() as u16),
        crate::STAT_U16 => Some(size_of::<u16>() as u16),
        crate::STAT_U32 => Some(size_of::<u32>() as u16),
        crate::STAT_U64 => Some(size_of::<u64>() as u16),
        crate::STAT_I8 => Some(size_of::<i8>() as u16),
        crate::STAT_I16 => Some(size_of::<i16>() as u16),
        crate::STAT_I32 => Some(size_of::<i32>() as u16),
        crate::STAT_I64 => Some(size_of::<i64>() as u16),
        _ => panic!("Invalid StatType given..."),
    }
}

pub enum NewStat {
    #[doc(hidden)]
    NewComponent(u16),
    Bytes(u16),
    Str(u16),
    USize,
    ISize,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
}

impl NewStat {
    pub fn len(&self) -> u16 {
        (match &self {
            &NewStat::NewComponent(v) => *v as usize,
            &NewStat::Bytes(v) => *v as usize,
            &NewStat::Str(v) => *v as usize,
            &NewStat::USize => size_of::<usize>(),
            &NewStat::ISize => size_of::<isize>(),
            &NewStat::U8 => size_of::<u8>(),
            &NewStat::U16 => size_of::<u16>(),
            &NewStat::U32 => size_of::<u32>(),
            &NewStat::U64 => size_of::<u64>(),
            &NewStat::I8 => size_of::<i8>(),
            &NewStat::I16 => size_of::<i16>(),
            &NewStat::I32 => size_of::<i32>(),
            &NewStat::I64 => size_of::<i64>(),
        }) as u16
    }
    pub fn to_id(&self) -> StatType {
        match &self {
            &NewStat::NewComponent(_) => STAT_NEWCOMPONENT,
            &NewStat::Bytes(_) => STAT_BYTES,
            &NewStat::Str(_) => STAT_STR,
            &NewStat::USize => STAT_USIZE,
            &NewStat::ISize => STAT_ISIZE,
            &NewStat::U8 => STAT_U8,
            &NewStat::U16 => STAT_U16,
            &NewStat::U32 => STAT_U32,
            &NewStat::U64 => STAT_U64,
            &NewStat::I8 => STAT_I8,
            &NewStat::I16 => STAT_I16,
            &NewStat::I32 => STAT_I32,
            &NewStat::I64 => STAT_I64,
        }
    }
}

impl CoreInterface {

    pub fn store_push_back<S: AsRef<str>, T>(&self, key: S, data: *mut T) {
        let key = key.as_ref();
        unsafe {
            (self.store_push_back.unwrap())(self.ctx, key.as_ptr(), key.len(), data as *mut _);
        }
    }
    pub fn store_push_front<S: AsRef<str>, T>(&self, key: S, data: *mut T) {
        let key = key.as_ref();
        unsafe {
            (self.store_push_front.unwrap())(self.ctx, key.as_ptr(), key.len(), data as *mut _);
        }
    }
    pub fn store_pop_back<S: AsRef<str>, T>(&self, key: S) -> *mut T {
        let key = key.as_ref();
        unsafe {
            (self.store_pop_back.unwrap())(self.ctx, key.as_ptr(), key.len()) as *mut T
        }
    }
    pub fn store_pop_front<S: AsRef<str>, T>(&self, key: S) -> *mut T {
        let key = key.as_ref();
        unsafe {
            (self.store_pop_front.unwrap())(self.ctx, key.as_ptr(), key.len()) as *mut T
        }
    }
    pub fn store_get_mut<S: AsRef<str>, T>(&self, key: S, index: usize) -> *mut T {
        let key = key.as_ref();
        unsafe {
            (self.store_get_mut.unwrap())(self.ctx, key.as_ptr(), key.len(), index) as *mut T
        }
    }
    /// Asks the fuzzer core to log a message
    pub fn log<S: AsRef<str>>(&self, log_level: LogLevel, msg: S) {
        let msg = msg.as_ref();
        unsafe {
            (self.log.unwrap())(self.ctx, log_level, msg.as_ptr(), msg.len());
        }
    }
    pub fn add_stat<S: AsRef<str>>(&self, tag: S, stat_type: NewStat) -> *mut c_void {
        let tag = tag.as_ref();
        unsafe {
            (self.add_stat.unwrap())(self.ctx, stat_type.to_id(), tag.as_ptr(), tag.len() as u16, stat_type.len())
        }
    }
}