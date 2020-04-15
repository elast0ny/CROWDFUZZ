use ::cflib::*;

use std::fs::OpenOptions;
use std::process::{Command, Stdio};
use std::time::Instant;

cfg_if::cfg_if! {
    if #[cfg(target_os = "windows")] {
        mod windows;
        use windows as os;
    } else {
        mod linux;
        use linux as os;
    }
}

use std::ffi::c_void;
use std::fs::File;
use std::io::{Seek, Write};

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(init, init);
cflib::register!(validate, validate);
cflib::register!(work, run_target);
cflib::register!(destroy, destroy);

/// Custom stats owned by the plugin
struct CustomStats {
    target_exec_time: &'static mut u64,
}

pub struct State {
    target_path: &'static str,
    target_args: Vec<&'static str>,
    target_input_file: Option<File>,
    last_run_time: u64,
    exit_status: CTuple,
    pub_chunk_list: &'static CVec,
    avg_denominator: &'static u64,
    stats: CustomStats,
}

extern "C" fn init(core_ptr: *mut CoreInterface) -> PluginStatus {
    let core = cflib::ctx_unchecked!(core_ptr);

    let mut state = unsafe {
        Box::new(State {
            target_path: "",
            target_args: Vec::new(),
            target_input_file: None,
            last_run_time: 0,
            exit_status: CTuple {
                first: 0,
                second: 0,
            },
            pub_chunk_list: &*std::ptr::null(),
            avg_denominator: &*std::ptr::null(),
            stats: CustomStats {
                target_exec_time: &mut *(core.add_stat(
                    &format!("{}target_exec_time{}", cflib::TAG_PREFIX_AVERAGE_STR, cflib::NUM_POSTFIX_US_STR),
                    NewStat::Number).unwrap() as *mut _),
            },
        })
    };

    *state.stats.target_exec_time = 0;

    // Add the keys that we control
    core.store_push_front(KEY_EXIT_STATUS_STR, &mut state.exit_status as *mut _);

    // Set private data
    core.priv_data = Box::into_raw(state) as *mut _;
    STATUS_SUCCESS
}

extern "C" fn validate(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let (core, state) = cflib::ctx_unchecked!(core_ptr, priv_data, State);

    let config_input_fpath = cflib::store_get_ref!(mandatory, str, core, KEY_CUR_INPUT_PATH_STR, 0);
    state.target_path = cflib::store_get_ref!(mandatory, str, core, KEY_TARGET_PATH_STR, 0);

    let mut i = 0;
    while let Some(tmp_str) = cflib::store_get_ref!(optional, str, core, KEY_TARGET_ARGS_STR, i) {
        i += 1;
        core.log(LOGLEVEL_DEBUG, &format!("Arg : {}", tmp_str));
        // Detect the use of on disk fuzzed input
        if tmp_str == "@@" {
            let f = match OpenOptions::new()
                .truncate(true)
                .create(true)
                .write(true)
                .open(config_input_fpath)
            {
                Ok(f) => f,
                Err(e) => {
                    core.log(
                        LOGLEVEL_ERROR,
                        &format!(
                            "Failed to create input file '{}' : {}",
                            config_input_fpath, e
                        ),
                    );
                    return STATUS_PLUGINERROR;
                }
            };

            state.target_input_file = Some(f);
            state.target_args.push(config_input_fpath);
        } else {
            state.target_args.push(tmp_str);
        }
    }
    // input bytes
    state.pub_chunk_list =
        cflib::store_get_ref!(mandatory, CVec, core, KEY_CUR_INPUT_CHUNKS_STR, 0);
    // Average denominator to calculate target avg exec speed
    state.avg_denominator = cflib::store_get_ref!(mandatory, u64, core, KEY_AVG_DENOMINATOR_STR, 0);

    core.log(
        LOGLEVEL_INFO,
        &format!("Running '{}' {:?}", state.target_path, state.target_args),
    );

    STATUS_SUCCESS
}

extern "C" fn destroy(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let core = cflib::ctx_unchecked!(core_ptr);

    let _state: Box<State> = unsafe { Box::from_raw(priv_data as *mut _) };
    let _: *mut c_void = core.store_pop_front(KEY_EXIT_STATUS_STR);

    STATUS_SUCCESS
}

extern "C" fn run_target(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let (core, state) = cflib::ctx_unchecked!(core_ptr, priv_data, State);

    // Update the target exec from the last run
    update_average(
        state.stats.target_exec_time,
        state.last_run_time,
        *state.avg_denominator,
    );

    let mut cmd = Command::new(state.target_path);
    cmd.args(&state.target_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    //TODO .current_dir()

    // Get updated list of input data chunks
    let chunks: &[CTuple] = state.pub_chunk_list.as_slice();

    // Write the input to disk if required
    match state.target_input_file {
        Some(ref mut f) => {
            let _ = (f.set_len(0), f.seek(std::io::SeekFrom::Start(0)));
            for chunk in chunks {
                let chunk_data: &[u8] =
                    unsafe { std::slice::from_raw_parts(chunk.second as _, chunk.first) };
                if let Err(e) = f.write_all(chunk_data) {
                    core.log(LOGLEVEL_ERROR, &format!("Failed to write input : {}", e));
                    return STATUS_PLUGINERROR;
                }
            }
            let _ = f.flush();
        }
        None => {
            cmd.stdin(Stdio::piped());
        }
    }

    // Spawn the target process
    let child_start: Instant = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            core.log(
                LOGLEVEL_ERROR,
                &format!(
                    "Failed to spawn child process '{}' {:?} : {}",
                    state.target_path, state.target_args, e
                ),
            );
            return STATUS_PLUGINERROR;
        }
    };

    // Sent input to process' stdin if needed
    if state.target_input_file.is_none() {
        let stdin = child.stdin.as_mut().unwrap();
        for chunk in chunks {
            let chunk_data: &[u8] =
                unsafe { std::slice::from_raw_parts(chunk.second as _, chunk.first) };
            if let Err(_) = stdin.write_all(chunk_data) {
                //maybe log here ? process didnt get all the input
                break;
            }
        }
    }

    //std::thread::sleep(std::time::Duration::from_secs(30));

    //TODO : Add some timeout mechanism
    let result = child.wait().unwrap();
    state.last_run_time = child_start.elapsed().as_micros() as u64;

    match os::get_exception(&result) {
        Some(exception) => {
            state.exit_status.first = 1;
            state.exit_status.second = exception as _;
        }
        None => {
            state.exit_status.first = 0;
            state.exit_status.second = result.code().unwrap() as _;
        }
    }

    STATUS_SUCCESS
}
