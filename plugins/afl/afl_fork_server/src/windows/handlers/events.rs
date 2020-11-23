use std::ffi::{CStr, CString};
use std::os::raw::c_void;
use std::ptr::null_mut;

use ::winapi::um::minwinbase::{
    EXCEPTION_ACCESS_VIOLATION, EXCEPTION_ILLEGAL_INSTRUCTION, EXCEPTION_INT_DIVIDE_BY_ZERO,
    EXCEPTION_PRIV_INSTRUCTION, EXCEPTION_STACK_OVERFLOW,
};
use ::winapi::um::winnt::{
    STATUS_FATAL_APP_EXIT, STATUS_HEAP_CORRUPTION, STATUS_STACK_BUFFER_OVERRUN,
};
use dynamorio_sys::*;

use super::*;

/// Gets called when a module is loaded by the target process
pub unsafe extern "C" fn event_module_load(
    drcontext: *mut c_void,
    info: *const module_data_t,
    loaded: i8,
) {
    let g = &mut *GLOBALS;
    let module_name = CStr::from_ptr(if (*info).names.exe_name.is_null() {
        dr_module_preferred_name(info)
    } else {
        (*info).names.exe_name
    });

    let module_name_str = module_name.to_str().unwrap();

    if let Some(dbg) = &mut g.debug_file {
        writeln!(dbg, "Module loaded : {}", module_name_str);
    }

    // If this module is the one container the target fuzz function
    if is_eq_lowercased(&g.options.target_module, &module_name_str) {
        let mut wrap_proc: *mut u8 = null_mut();

        match &g.options.target_function {
            TargetFunction::Offset(offset) => {
                wrap_proc = (*info).__bindgen_anon_1.start.add(*offset);
            }
            TargetFunction::Symbol(sym) => {
                let target_func_name = CString::new(sym.clone()).unwrap();
                wrap_proc = match dr_get_proc_address(
                    (*info).__bindgen_anon_1.handle,
                    target_func_name.as_ptr(),
                ) {
                    Some(p) => p as _,
                    None => {
                        let mut tmp = 0;
                        drsym_init(null_mut());
                        drsym_lookup_symbol(
                            (*info).full_path,
                            target_func_name.as_ptr(),
                            &mut tmp,
                            0,
                        );
                        drsym_exit();
                        tmp as _
                    }
                };

                if wrap_proc.is_null() {
                    (Message::Error(format!(
                        "Failed to find fuzz method '{}' in target module '{}'...",
                        sym, g.options.target_module
                    )))
                    .to_writer(&mut g.server_sock)
                    .unwrap();
                    dr_exit_process(1);
                }

                match g.options.persistence_mode {
                    PersistenceMode::Native => {
                        drwrap_wrap_ex(
                            wrap_proc,
                            Some(pre_fuzz_handler),
                            Some(post_fuzz_handler),
                            null_mut(),
                            g.options.calling_convention as u32,
                        );
                    }
                    PersistenceMode::InApp => {
                        drwrap_wrap_ex(
                            wrap_proc,
                            Some(pre_loop_start_handler),
                            None,
                            null_mut(),
                            g.options.calling_convention as u32,
                        );
                    }
                };
            }
        };
    }

    if g.debug_file.is_some() {
        if is_eq_lowercased(module_name_str, "ws2_32.dll") {
            if let Some(proc_addr) =
                dr_get_proc_address((*info).__bindgen_anon_1.handle, b"recvfrom\0".as_ptr() as _)
            {
                drwrap_wrap(proc_addr as _, Some(recvfrom_interceptor), None);
            };
            if let Some(proc_addr) =
                dr_get_proc_address((*info).__bindgen_anon_1.handle, b"recv\0".as_ptr() as _)
            {
                drwrap_wrap(proc_addr as _, Some(recv_interceptor), None);
            };
        } else if is_eq_lowercased(module_name_str, "kernel32.dll") {
            if let Some(proc_addr) = dr_get_proc_address(
                (*info).__bindgen_anon_1.handle,
                b"CreateFileW\0".as_ptr() as _,
            ) {
                drwrap_wrap(proc_addr as _, Some(createfilew_interceptor), None);
            };
            if let Some(proc_addr) = dr_get_proc_address(
                (*info).__bindgen_anon_1.handle,
                b"CreateFileA\0".as_ptr() as _,
            ) {
                drwrap_wrap(proc_addr as _, Some(createfilea_interceptor), None);
            };
        } else if is_eq_lowercased(module_name_str, "kernelbase.dll") {
            // Since Win8, software can use _fastfail() to trigger an exception that cannot be caught.
            // This is a problem for winafl as it also means DR won't be able to see it. Good thing is that
            // usually those routines (__report_gsfailure for example) accounts for platforms that don't
            // have support for fastfail. In those cases, they craft an exception record and pass it
            // to UnhandledExceptionFilter.
            //
            // To work around this we set up two hooks:
            //   (1) IsProcessorFeaturePresent(PF_FASTFAIL_AVAILABLE): to lie and pretend that the
            //       platform doesn't support fastfail.
            //   (2) UnhandledExceptionFilter: to intercept the exception record and forward it
            //       to winafl's exception handler.
            if let Some(proc_addr) = dr_get_proc_address(
                (*info).__bindgen_anon_1.handle,
                b"IsProcessorFeaturePresent\0".as_ptr() as _,
            ) {
                drwrap_wrap(
                    proc_addr as _,
                    Some(isprocessorfeaturepresent_interceptor_pre),
                    Some(isprocessorfeaturepresent_interceptor_post),
                );
            };
            if let Some(proc_addr) = dr_get_proc_address(
                (*info).__bindgen_anon_1.handle,
                b"UnhandledExceptionFilter\0".as_ptr() as _,
            ) {
                drwrap_wrap(
                    proc_addr as _,
                    Some(unhandledexceptionfilter_interceptor_pre),
                    None,
                );
            };
        }
    }
    if is_eq_lowercased(module_name_str, "verifier.dll") {
        if let Some(proc_addr) = dr_get_proc_address(
            (*info).__bindgen_anon_1.handle,
            b"VerifierStopMessage\0".as_ptr() as _,
        ) {
            drwrap_wrap(
                proc_addr as _,
                Some(verfierstopmessage_interceptor_pre),
                None,
            );
        };
    }

    // Save info for this module
    g.modules.insert(module_name_str.to_string(), *info);
}

/// Gets called when a module is unloaded by the target process
pub unsafe extern "C" fn event_module_unload(rcontext: *mut c_void, info: *const module_data_t) {
    let g = &mut *GLOBALS;

    let module_name = CStr::from_ptr(if (*info).names.exe_name.is_null() {
        dr_module_preferred_name(info)
    } else {
        (*info).names.exe_name
    });

    let module_name_str = module_name.to_str().unwrap();

    g.modules.remove(module_name_str);
}

pub unsafe extern "C" fn event_exit() {
    let g = &mut *GLOBALS;

    drx_exit();
    drmgr_exit();
}

pub unsafe extern "C" fn event_exception(
    _drcontext: *mut c_void,
    excpt: *mut dr_exception_t,
) -> i8 {
    let g = &mut *GLOBALS;
    let exception_code = (*(*excpt).record).ExceptionCode;
    if let Some(dbg) = &mut g.debug_file {
        writeln!(dbg, "Exception caught: {:X}", exception_code);
    }

    if exception_code == EXCEPTION_ACCESS_VIOLATION
        || exception_code == EXCEPTION_ILLEGAL_INSTRUCTION
        || exception_code == EXCEPTION_PRIV_INSTRUCTION
        || exception_code == EXCEPTION_INT_DIVIDE_BY_ZERO
        || exception_code == STATUS_HEAP_CORRUPTION
        || exception_code == EXCEPTION_STACK_OVERFLOW
        || exception_code == STATUS_STACK_BUFFER_OVERRUN
        || exception_code == STATUS_FATAL_APP_EXIT
    {
        if let Some(dbg) = &mut g.debug_file {
            writeln!(dbg, "crashed");
        }

        // Tell server the target crashed
        (Message::ExecResult(cflib::TargetExitStatus::Crash(exception_code as _)))
            .to_writer(&mut g.server_sock)
            .unwrap();

        dr_exit_process(1);
    }

    1
}

/*
static void event_thread_init(void *drcontext)
{
  void **thread_data;

  thread_data = (void **)dr_thread_alloc(drcontext, 2 * sizeof(void *));
  thread_data[0] = 0;
  if(options.thread_coverage) {
    thread_data[1] = winafl_data.fake_afl_area;
  } else {
    thread_data[1] = winafl_data.afl_area;
  }
  drmgr_set_tls_field(drcontext, winafl_tls_field, thread_data);
}

static void event_thread_exit(void *drcontext)
{
  void *data = drmgr_get_tls_field(drcontext, winafl_tls_field);
  dr_thread_free(drcontext, data, 2 * sizeof(void *));
}
*/
