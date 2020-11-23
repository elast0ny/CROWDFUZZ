
use std::ffi::{CStr};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::mem::{size_of, MaybeUninit};
use std::net::TcpStream;
use std::os::raw::{c_char, c_int, c_uint};
use std::collections::HashMap;
use std::ptr::null_mut;

use dynamorio_sys::*;

use super::*;
use crate::Result;

pub struct FuncCtx {
    pub xsp: reg_t,
    pub func_pc: app_pc,
}
impl Default for FuncCtx {
    fn default() -> Self {
            unsafe {MaybeUninit::zeroed().assume_init()}  
    }
}
pub struct Globals {
    pub server_sock: TcpStream,
    pub client_id: c_uint,
    pub modules: HashMap<String, dr::module_data_t>,
    pub debug_file: Option<File>,
    pub options: ClientOptions,
    pub tls_field: c_int,
    pub afl_area: *mut u8,
    pub trace_bits: [u8; afl_lib::MAP_SIZE],
    pub cur_iterations: usize,
    pub func_ctx: FuncCtx,
}
impl Globals {
    // Ininitialzes our state from the drrun.exe arguments
    pub fn new(id: c_uint, argc: c_int, argv: *const *const c_char) -> Result<Self> {
        if argc <= 0 || argv.is_null() {
            return Err(From::from("Failed to parse args".to_string()));
        }

        let mut args: Vec<&str> = Vec::with_capacity(argc as usize);
        // Convert C style args
        for i in 0..argc {
            let cstr = unsafe {
                let argv_entry = *argv.add(i as usize);
                if argv.is_null() {
                    return Err(From::from(format!("argv[{}] is null...", i)));
                }
                CStr::from_ptr(argv_entry)
            };
            args.push(match cstr.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Err(From::from(format!("Invalid utf8 in argv[{}]", i)));
                }
            });
        }

        // For now we only take one argument
        if args.len() != 1 {
            return Err(From::from(format!(
                "DRIO client only expects 1 argument but got {}",
                args.len()
            )));
        }

        // Connect to server
        let server_addr = args.pop().unwrap();
        let mut server_sock = match TcpStream::connect(server_addr) {
            Ok(s) => s,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to connect to {} : {}",
                    server_addr, e
                )));
            }
        };

        // Receive options
        let options = match ClientOptions::from_reader(&mut server_sock) {
            Ok(o) => o,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to receive options from {} : {}",
                    server_addr, e
                )));
            }
        };

        let mut debug_file = None;

        // Open output file
        if let Some(ref fpath) = options.debug_fpath {
            debug_file = match OpenOptions::new().write(true).append(true).open(fpath) {
                Ok(mut f) => {
                    writeln!(&mut f, "\n--------------------------\nDRIO client initialized\n--------------------------");
                    Some(f)
                }
                Err(e) => {
                    return Err(From::from(format!(
                        "Failed to open output file {} : {}",
                        fpath, e
                    )));
                }
            };
        }

        Ok(Self {
            client_id: id,
            server_sock,
            debug_file,
            modules: HashMap::new(),
            options,
            tls_field: -1,
            afl_area: null_mut(),
            trace_bits: [0; afl_lib::MAP_SIZE],
            cur_iterations: 0,
            func_ctx: FuncCtx::default(),
        })
    }
}

pub static mut GLOBALS: *mut Globals = std::ptr::null_mut();


/// Entrypoint for the drrun.exe client dll
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
    GLOBALS = Box::leak(Box::new(Globals::new(id, argc, argv).unwrap()));
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
        _ => {}
    };

    drmgr_register_module_load_event(Some(event_module_load));
    drmgr_register_module_unload_event(Some(event_module_unload));
}


