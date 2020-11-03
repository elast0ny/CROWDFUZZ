use super::dr::*;
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

static mut OPTIONS: *mut ClientOptions = std::ptr::null_mut();

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
    OPTIONS = Box::leak(Box::new(ClientOptions::default()));
    let options = &mut *OPTIONS;

    dr_register_exit_event(Some(event_exit));
    drmgr_register_exception_event(Some(event_exception));

    match options.coverage_kind {
        CoverageType::BasicBlock => {
            //drmgr_register_bb_instrumentation_event(NULL, instrument_bb_coverage, NULL);
        }, 
        CoverageType::Edge => {
            //drmgr_register_bb_instrumentation_event(NULL, instrument_edge_coverage, NULL);
        }
    };

    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);
}

unsafe extern "C" fn event_exit() {
    let options = &mut *OPTIONS;

    if options.debug_mode {

    }

    drx_exit();
    drmgr_exit();
}

unsafe extern "C" fn event_exception(_drcontext: *mut c_void, excpt: *mut dr_exception_t) -> i8 {
    let options = &mut *OPTIONS;
    let exception_code = (*(*excpt).record).ExceptionCode;
    if options.debug_mode {
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
        if options.debug_mode {
            //dr_fprintf(winafl_data.log, "crashed\n")
        } else {
            //WriteCommandToPipe('C');
        }

        dr_exit_process(1);
    }

    1
}
