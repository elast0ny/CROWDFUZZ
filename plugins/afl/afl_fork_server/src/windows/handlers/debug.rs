use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::raw::c_void;
use std::ptr::null_mut;

use widestring::U16CStr;
use winapi::um::winnt::{PF_FASTFAIL_AVAILABLE, EXCEPTION_POINTERS, PEXCEPTION_POINTERS};
use dynamorio_sys::*;
use ::winapi::um::winnt::STATUS_HEAP_CORRUPTION;

use super::*;

pub unsafe extern "C" fn createfilew_interceptor(wrapcxt: *mut c_void, _user_data: *mut *mut c_void)
{
    let filenamew: &U16CStr = U16CStr::from_ptr_str(drwrap_get_arg(wrapcxt, 0) as _);

    if let Some(ref mut dbg) = (&mut *GLOBALS).debug_file {
        writeln!(dbg, "CreateFileW({:?})", filenamew);
    }
}
pub unsafe extern "C" fn createfilea_interceptor(wrapcxt: *mut c_void, _user_data: *mut *mut c_void)
{
    let filename: &CStr = CStr::from_ptr(drwrap_get_arg(wrapcxt, 0) as _);

    if let Some(ref mut dbg) = (&mut *GLOBALS).debug_file {
        writeln!(dbg, "CreateFileA({:?})", filename);
    }
}

pub unsafe extern "C" fn verfierstopmessage_interceptor_pre(_wrapcxt: *mut c_void, _user_data: *mut *mut c_void)
{
    let mut exception_record: EXCEPTION_RECORD = MaybeUninit::zeroed().assume_init();
    let mut dr_exception: dr_exception_t = MaybeUninit::zeroed().assume_init();
    
    dr_exception.record = &mut exception_record;
    exception_record.ExceptionCode = STATUS_HEAP_CORRUPTION;

    event_exception(null_mut(), &mut dr_exception);
}


pub unsafe extern "C" fn recvfrom_interceptor(_wrapcxt: *mut c_void, _user_data: *mut *mut c_void)
{
    if let Some(ref mut dbg) = (&mut *GLOBALS).debug_file {
        writeln!(dbg, "recvfrom()");
    }
}

pub unsafe extern "C" fn recv_interceptor(_wrapcxt: *mut c_void, _user_data: *mut *mut c_void)
{
    if let Some(ref mut dbg) = (&mut *GLOBALS).debug_file {
        writeln!(dbg, "recv()");
    }
}

pub unsafe extern "C" fn isprocessorfeaturepresent_interceptor_pre(wrapcxt: *mut c_void, user_data: *mut *mut c_void)
{
    let feature = drwrap_get_arg(wrapcxt, 0) as DWORD;
    *user_data = feature as *mut c_void;
}

pub unsafe extern "C" fn isprocessorfeaturepresent_interceptor_post(wrapcxt: *mut c_void, user_data: *mut c_void)
{
    let feature: DWORD = user_data as DWORD;
    if feature == PF_FASTFAIL_AVAILABLE {
        if let Some(ref mut dbg) = (&mut *GLOBALS).debug_file {
            writeln!(dbg, "About to make IsProcessorFeaturePresent({}) return 0", feature);
        }

        // Make the software thinks that _fastfail() is not supported.
        drwrap_set_retval(wrapcxt, null_mut());
    }
}


pub unsafe extern "C" fn unhandledexceptionfilter_interceptor_pre(wrapcxt: *mut c_void, _user_data: *mut *mut c_void)
{
    let exception: &EXCEPTION_POINTERS = &*(drwrap_get_arg(wrapcxt, 0) as PEXCEPTION_POINTERS);
    let mut dr_exception: dr_exception_t = MaybeUninit::zeroed().assume_init();

    // Fake an exception
    dr_exception.record = exception.ExceptionRecord as _;
    event_exception(null_mut(), &mut dr_exception);
}
