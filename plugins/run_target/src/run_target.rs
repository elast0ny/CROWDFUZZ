use std::collections::HashMap;
use std::fs::File;
use std::io::{Seek, Write};
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ::cflib::*;
use ::wait_timeout::ChildExt;

cfg_if::cfg_if! {
    if #[cfg(target_os = "windows")] {
        mod windows;
        use windows as os;
    } else {
        mod linux;
        use linux as os;
    }
}

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, run_target);
cflib::register!(unload, destroy);

struct State {
    /// Reference to the currently selected input
    cur_input: &'static CfInput,
    target_path: &'static String,
    avg_denominator: &'static u64,
    target_args: Vec<String>,
    input_file: Option<File>,
    target_exec_time: StatNum,
    exit_status: TargetExitStatus,

    target_input_path: Option<String>,
    target_working_dir: Option<String>,
    target_timeout_ms: Option<Duration>,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let mut state = Box::new(unsafe {
        State {
            exit_status: TargetExitStatus::Normal(0),
            target_path: MaybeUninit::zeroed().assume_init(),
            cur_input: MaybeUninit::zeroed().assume_init(),
            avg_denominator: MaybeUninit::zeroed().assume_init(),
            target_args: Vec::new(),
            input_file: None,
            target_exec_time: match core.add_stat(STAT_TARGET_EXEC_TIME, NewStat::Num(0)) {
                Ok(StatVal::Num(v)) => v,
                _ => return Err(From::from("Failed to reserve stat".to_string())),
            },
            target_input_path: None,
            target_working_dir: None,
            target_timeout_ms: None,
        }
    });

    state.target_path = raw_to_ref!(*store.get(STORE_TARGET_BIN).unwrap(), String);
    state.avg_denominator = raw_to_ref!(*store.get(STORE_AVG_DENOMINATOR).unwrap(), u64);
    // Make sure target is a file
    if !Path::new(state.target_path).is_file() {
        core.log(
            LogLevel::Error,
            &format!("Failed to find target binary '{}'", state.target_path),
        );
        return Err(From::from("Invalid target binary path".to_string()));
    }

    // Parse our config values
    let plugin_conf = raw_to_ref!(*store.get(STORE_PLUGIN_CONF).unwrap(), HashMap<String, String>);
    state.load_config(core, plugin_conf)?;

    // Add exit_status to store
    if store.get(STORE_EXIT_STATUS).is_some() {
        core.log(
            LogLevel::Error,
            "Another plugin is already filling exit_status !",
        );
        return Err(From::from("Duplicate run target plugins".to_string()));
    }
    store.insert(
        STORE_EXIT_STATUS.to_string(),
        ref_to_raw!(state.exit_status),
    );

    // Build arg list swapping @@ for file path
    let target_args = raw_to_ref!(*store.get(STORE_TARGET_ARGS).unwrap(), Vec<String>);
    let mut input_path = PathBuf::new();
    for arg in target_args {
        if "@@" == arg {
            match state.input_file {
                Some(_) => state
                    .target_args
                    .push(input_path.to_str().unwrap().to_string()),
                None => {
                    input_path.push(raw_to_ref!(*store.get(STORE_STATE_DIR).unwrap(), String));
                    if let Some(ref p) = state.target_input_path {
                        input_path.push(p);
                    } else {
                        input_path.push("cur_input");
                    }

                    state
                        .target_args
                        .push(input_path.to_str().unwrap().to_string());
                    state.input_file = Some(match File::create(&input_path) {
                        Ok(f) => f,
                        Err(e) => {
                            core.log(
                                LogLevel::Error,
                                &format!(
                                    "Failed to create input file {} : {}",
                                    input_path.to_string_lossy(),
                                    e
                                ),
                            );
                            return Err(From::from(
                                "Failed to create input file for target".to_string(),
                            ));
                        }
                    });
                }
            };
        } else {
            state.target_args.push(arg.clone());
        }
    }

    core.log(
        LogLevel::Info,
        &format!("Running '{}' {:?}", state.target_path, state.target_args),
    );
    Ok(Box::into_raw(state) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);
    // Make sure someone is providing us input bytes
    match store.get(STORE_INPUT_BYTES) {
        Some(v) => state.cur_input = raw_to_ref!(*v, CfInput),
        None => {
            core.log(LogLevel::Error, "No plugin created input_bytes !");
            return Err(From::from("No input".to_string()));
        }
    };

    Ok(())
}

// Perform our task in the fuzzing loop
fn run_target(
    core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    let mut cmd = Command::new(state.target_path);
    cmd.args(&state.target_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(ref d) = state.target_working_dir {
        cmd.current_dir(d);
    }

    if let Some(ref mut f) = state.input_file {
        for chunk in &state.cur_input.chunks {
            let _ = (f.set_len(0), f.seek(std::io::SeekFrom::Start(0)));
            if let Err(e) = f.write_all(chunk) {
                core.log(
                    LogLevel::Error,
                    &format!("Failed to write target input : {}", e),
                );
                return Err(From::from("Failed to write target input".to_string()));
            }
        }
        let _ = f.flush();
    } else {
        cmd.stdin(Stdio::piped());
    }

    let child_start: Instant = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            core.log(
                LogLevel::Error,
                &format!(
                    "Failed to spawn child process '{}' {:?} : {}",
                    state.target_path, state.target_args, e
                ),
            );
            return Err(From::from("Failed to spawn target".to_string()));
        }
    };

    if state.input_file.is_none() {
        let stdin = child.stdin.as_mut().unwrap();
        for chunk in &state.cur_input.chunks {
            if let Err(e) = stdin.write_all(chunk) {
                core.log(
                    LogLevel::Error,
                    &format!("Failed to write target stdin : {}", e),
                );
                return Err(From::from("Failed to write target stdin".to_string()));
            }
        }
    }

    //TODO : implement timeout
    let result = if let Some(timeout) = state.target_timeout_ms {
        child.wait_timeout(timeout).unwrap()
    } else {
        Some(child.wait().unwrap())
    };

    update_average(
        state.target_exec_time.val,
        child_start.elapsed().as_micros() as u64,
        *state.avg_denominator,
    );

    match result {
        None => {
            let _ = child.kill();
            state.exit_status = TargetExitStatus::Timeout
        }
        Some(ref r) => {
            match os::get_exception(&r) {
                Some(exception) => {
                    state.exit_status = TargetExitStatus::Crash(exception);
                }
                None => {
                    state.exit_status = TargetExitStatus::Normal(r.code().unwrap() as _);
                }
            };
        }
    };

    Ok(())
}

// Unload and free our resources
fn destroy(
    _core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let _state = box_take!(plugin_ctx, State);

    let _ = store.remove(STORE_EXIT_STATUS);

    Ok(())
}

impl State {
    /// Parse the plugin_conf for our values
    pub fn load_config(
        &mut self,
        core: &mut dyn PluginInterface,
        conf: &HashMap<String, String>,
    ) -> Result<()> {
        if let Some(v) = conf.get("target_input_path") {
            self.target_input_path = Some(v.clone());
        }

        if let Some(v) = conf.get("target_timeout_ms") {
            match v.parse::<usize>() {
                Ok(num) => self.target_timeout_ms = Some(Duration::from_millis(num as _)),
                Err(e) => {
                    core.log(
                        LogLevel::Error,
                        &format!(
                            "Failed to parse number in target_timeout_ms config '{}' : {}",
                            v, e
                        ),
                    );
                    return Err(From::from("Invalid config".to_string()));
                }
            }
        }

        if let Some(v) = conf.get("target_wd") {
            // Make sure its a valid directory
            if !Path::new(v.as_str()).is_dir() {
                core.log(
                    LogLevel::Error,
                    &format!("Target working directory does not exist '{}'", v),
                );
                return Err(From::from("Invalid config".to_string()));
            }
            self.target_working_dir = Some(v.clone());
        }
        Ok(())
    }
}
