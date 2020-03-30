use std::ffi::c_void;

use crate::core::Core;
use ::log::*;

pub extern "C" fn store_push_back_cb(
    ctx: *const cflib::CoreCtx,
    key: *const u8,
    key_len: usize,
    data: *mut c_void,
) {
    let core: &mut Core = unsafe { &mut *(ctx as *mut Core) };
    let store_key: String = String::from(unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(key, key_len))
    });

    core.store_push_back(store_key, data);
}
pub extern "C" fn store_push_front_cb(
    ctx: *const cflib::CoreCtx,
    key: *const u8,
    key_len: usize,
    data: *mut c_void,
) {
    let core: &mut Core = unsafe { &mut *(ctx as *mut Core) };
    let store_key: String = String::from(unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(key, key_len))
    });

    core.store_push_front(store_key, data);
}

pub extern "C" fn store_pop_back_cb(
    ctx: *const cflib::CoreCtx,
    key: *const u8,
    key_len: usize,
) -> *mut c_void {
    let core: &mut Core = unsafe { &mut *(ctx as *mut Core) };
    let store_key: &str =
        unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(key, key_len)) };

    core.store_pop_back(store_key)
}
pub extern "C" fn store_pop_front_cb(
    ctx: *const cflib::CoreCtx,
    key: *const u8,
    key_len: usize,
) -> *mut c_void {
    let core: &mut Core = unsafe { &mut *(ctx as *mut Core) };
    let store_key: &str =
        unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(key, key_len)) };

    core.store_pop_front(store_key)
}
pub extern "C" fn store_get_mut_cb(
    ctx: *const cflib::CoreCtx,
    key: *const u8,
    key_len: usize,
    index: usize,
) -> *mut c_void {
    let core: &mut Core = unsafe { &mut *(ctx as *mut Core) };
    let store_key: &str =
        unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(key, key_len)) };

    core.store_get_mut(store_key, index)
}
pub extern "C" fn store_len_cb(ctx: *const cflib::CoreCtx, key: *const u8, key_len: usize) -> usize {
    let core: &mut Core = unsafe { &mut *(ctx as *mut Core) };
    let store_key: &str =
        unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(key, key_len)) };

    core.store_len(store_key)
}

pub extern "C" fn log_cb(
    ctx: *const cflib::CoreCtx,
    log_level: cflib::LogLevel,
    msg: *const u8,
    msg_len: usize,
) {
    let core: &mut Core = unsafe { &mut *(ctx as *mut Core) };
    let log_msg: &str =
        unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(msg, msg_len)) };
    let plugin_name: &str = (unsafe { core.plugin_chain.get_unchecked(core.cur_plugin_id) }).name();

    match log_level {
        cflib::LOGLEVEL_INFO => info!("[{}] {}", plugin_name, log_msg),
        cflib::LOGLEVEL_WARN => warn!("[{}] {}", plugin_name, log_msg),
        cflib::LOGLEVEL_ERROR => error!("[{}] {}", plugin_name, log_msg),
        cflib::LOGLEVEL_DEBUG => debug!("[{}] {}", plugin_name, log_msg),
        cflib::LOGLEVEL_TRACE => trace!("[{}] {}", plugin_name, log_msg),
        _ => error!(
            "[{}] [INVALID LOG LEVEL : {}] {}",
            plugin_name, log_level, log_msg
        ),
    }
}

pub extern "C" fn add_stat_cb(
    ctx: *const cflib::CoreCtx,
    stat_type: cflib::StatType,
    tag_ptr: *const u8,
    tag_len: u16,
    size_required: u16,
) -> *mut c_void {
    let core: &mut Core = unsafe { &mut *(ctx as *mut Core) };
    let tag_copy = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(tag_ptr, tag_len as usize))
    };

    core.stats.add(stat_type, tag_copy, size_required)
}
