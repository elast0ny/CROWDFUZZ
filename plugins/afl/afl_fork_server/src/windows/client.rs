use super::dr::*;
use std::ffi::CStr;
use std::mem::{size_of, MaybeUninit};
use std::os::raw::{c_char, c_int, c_void};

use super::*;

use ::winapi::um::minwinbase::{
    EXCEPTION_ACCESS_VIOLATION, EXCEPTION_ILLEGAL_INSTRUCTION, EXCEPTION_INT_DIVIDE_BY_ZERO,
    EXCEPTION_PRIV_INSTRUCTION, EXCEPTION_STACK_OVERFLOW,
};
use ::winapi::um::winnt::{
    STATUS_FATAL_APP_EXIT, STATUS_HEAP_CORRUPTION, STATUS_STACK_BUFFER_OVERRUN,
};

static mut GLOBALS: *mut Globals = std::ptr::null_mut();

#[no_mangle]
unsafe extern "C" fn dr_client_main(id: client_id_t, argc: c_int, argv: *const *const c_char) {
    let mut ops: drreg_options_t = MaybeUninit::zeroed().assume_init();
    ops.struct_size = size_of::<drreg_options_t>();
    ops.num_spill_slots = 2;
    ops.conservative = 0;

    dr_set_client_name(b"WinAfl\0".as_ptr() as _, b"\0".as_ptr() as _);
    drmgr_init();
    drx_init();
    drreg_init(&mut ops);
    drwrap_init();

    // Receive options from parent
    GLOBALS = Box::leak(Box::new(Globals::default()));
    let g = &mut *GLOBALS;

    dr_register_exit_event(Some(event_exit));
    drmgr_register_exception_event(Some(event_exception));

    match g.options.coverage_kind {
        CoverageType::BasicBlock => {
            //drmgr_register_bb_instrumentation_event(NULL, instrument_bb_coverage, NULL);
        }
        CoverageType::Edge => {
            //drmgr_register_bb_instrumentation_event(NULL, instrument_edge_coverage, NULL);
        }
    };

    drmgr_register_module_load_event(Some(event_module_load));
    drmgr_register_module_unload_event(Some(event_module_unload));
}

unsafe extern "C" fn event_exit() {
    let g = &mut *GLOBALS;

    if g.options.debug_mode {}

    drx_exit();
    drmgr_exit();
}

unsafe extern "C" fn event_exception(_drcontext: *mut c_void, excpt: *mut dr_exception_t) -> i8 {
    let g = &mut *GLOBALS;
    let exception_code = (*(*excpt).record).ExceptionCode;
    if g.options.debug_mode {
        //dr_fprintf(winafl_data.log, "Exception caught: %x\n", exception_code)
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
        if g.options.debug_mode {
            //dr_fprintf(winafl_data.log, "crashed\n")
        } else {
            //WriteCommandToPipe('C');
        }

        dr_exit_process(1);
    }

    1
}

unsafe extern "C" fn event_module_load(
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

    if g.options.debug_mode {
        //dr_fprintf(winafl_data.log, "Module loaded, %s\n", module_name);
    }
}

unsafe extern "C" fn event_module_unload(rcontext: *mut c_void, info: *const module_data_t) {
    let g = &mut *GLOBALS;
}
