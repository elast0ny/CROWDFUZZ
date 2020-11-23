use std::os::raw::c_void;

use dynamorio_sys::*;

use super::*;

pub unsafe extern "C" fn pre_loop_start_handler(wrapcxt: *mut c_void, user_data: *mut *mut c_void)
{
    let g = &mut *GLOBALS;
    let drcontext = drwrap_get_drcontext(wrapcxt);
    
    if let Some(dbg) = g.debug_file {
        writeln!(dbg, "In pre_loop_start_handler");
    }

    // Potentially tell server we are exiting if we hit iteration count
    if g.options.fuzz_iterations == g.cur_iterations {
        Message::Exiting.to_writer(&mut g.server_sock).unwrap();
        dr_exit_process(0);
        panic!("Should've exited...");
    }
    
    // Tell server we are ready for next input    
    g.cur_iterations += 1;
    Message::ReqNextInput.to_writer(&mut g.server_sock).unwrap();

    // Wait for next input
    match <Message>::from_reader(&mut g.server_sock).unwrap() {
        Message::NextInputReady => {},
        _ => {
            Message::Error("Unexpected command".to_string()).to_writer(&mut g.server_sock).unwrap();
            dr_exit_process(1);
            panic!("Should've exited...");
        }
    };

    // Zero out trace_bits for next run
    for b in g.trace_bits.iter_mut() {
        *b = 0x00;
    }

    match (g.options.coverage_kind, g.options.thread_coverage) {
        (CoverageType::Edge, _) | (_, true) => {
            let thread_data = drmgr_get_tls_field(drcontext as _, g.tls_field) as *mut *mut u8;
            *thread_data = std::ptr::null_mut();
            *thread_data.add(1) = g.afl_area;
        },
        _=>{},
    };
}

pub unsafe extern "C" fn pre_fuzz_handler(wrapcxt: *mut c_void, user_data: *mut *mut c_void)
{
    let g = &mut *GLOBALS;
    let drcontext = drwrap_get_drcontext(wrapcxt);

    if let Some(dbg) = g.debug_file {
        writeln!(dbg, "In pre_fuzz_handler");
    }
    
    let target_to_fuzz: app_pc = drwrap_get_func(wrapcxt);
    let mc: *mut dr_mcontext_t = drwrap_get_mcontext_ex(wrapcxt, dr_mcontext_flags_t_DR_MC_ALL);

    g.func_ctx.xsp = (*mc).__bindgen_anon_4.xsp;
    g.func_ctx.func_pc = target_to_fuzz;

    if(!options.debug_mode) {
		WriteCommandToPipe('P');
		command = ReadCommandFromPipe();

        if(command != 'F') {
            if(command == 'Q') {
                dr_exit_process(0);
            } else {
                DR_ASSERT_MSG(false, "unrecognized command received over pipe");
            }
        }
    }

    //save or restore arguments
    if (!options.no_loop) {
        if (fuzz_target.iteration == 0) {
            for (i = 0; i < options.num_fuz_args; i++)
                options.func_args[i] = drwrap_get_arg(wrapcxt, i);
        } else {
            for (i = 0; i < options.num_fuz_args; i++)
                drwrap_set_arg(wrapcxt, i, options.func_args[i]);
        }
    }

    memset(winafl_data.afl_area, 0, MAP_SIZE);

    if(options.coverage_kind == COVERAGE_EDGE || options.thread_coverage) {
        void **thread_data = (void **)drmgr_get_tls_field(drcontext, winafl_tls_field);
        thread_data[0] = 0;
        thread_data[1] = winafl_data.afl_area;
    }
    */
}

pub unsafe extern "C" fn post_fuzz_handler(wrapcxt: *mut c_void, user_data: *mut c_void)
{
    /*
    dr_mcontext_t *mc;
    mc = drwrap_get_mcontext(wrapcxt);

    if(!options.debug_mode) {
		WriteCommandToPipe('K');
    } else {
        debug_data.post_handler_called++;
        dr_fprintf(winafl_data.log, "In post_fuzz_handler\n");
    }

    /* We don't need to reload context in case of network-based fuzzing. */
    if (options.no_loop)
        return;

    fuzz_target.iteration++;
    if(fuzz_target.iteration == options.fuzz_iterations) {
        dr_exit_process(0);
    }

    mc->xsp = fuzz_target.xsp;
    mc->pc = fuzz_target.func_pc;
    drwrap_redirect_execution(wrapcxt);
    */
}
