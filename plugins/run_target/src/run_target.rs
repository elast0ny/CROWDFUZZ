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
    input_file: Option<File>,
    exec_time: u64,
    avg_exec_time: StatNum,
    cur_input: &'static CfInput,
    avg_denominator: &'static u64,
    exit_status: TargetExitStatus,
    cmd: Command,
    target_input_path: Option<String>,
    target_working_dir: Option<String>,
    target_timeout_ms: Option<Duration>,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    // Make sure target_bin points to a file
    let target_bin_path: &String = unsafe { store.as_ref(STORE_TARGET_BIN, Some(core))? };
    if !Path::new(target_bin_path).is_file() {
        core.error(&format!(
            "Failed to find target binary '{}'",
            target_bin_path
        ));
        return Err(From::from("Invalid target binary path".to_string()));
    }

    #[allow(invalid_value)]
    let mut s = Box::new(unsafe {
        State {
            exit_status: TargetExitStatus::Normal(0),
            input_file: None,
            exec_time: 0,
            target_input_path: None,
            target_working_dir: None,
            target_timeout_ms: None,
            cmd: Command::new(target_bin_path),
            // Stats
            avg_exec_time: core.new_stat_num(STAT_TARGET_EXEC_TIME, 0)?,
            // Core store values
            avg_denominator: store.as_ref(STORE_AVG_DENOMINATOR, Some(core))?,
            // Plugin store values
            cur_input: MaybeUninit::zeroed().assume_init(),
        }
    });

    //close stdout and stderr
    s.cmd.stdout(Stdio::null()).stderr(Stdio::null());

    // Insert our store values
    // EXIT_STATUS
    store.insert_exclusive(STORE_EXIT_STATUS, &s.exit_status, Some(core))?;
    // TARGET_EXEC_TIME
    store.insert_exclusive(STORE_TARGET_EXEC_TIME, &s.exec_time, Some(core))?;
    // AVG_TARGET_EXEC_TIME
    store.insert_exclusive(
        STORE_AVG_TARGET_EXEC_TIME,
        s.avg_exec_time.val,
        Some(core),
    )?;

    // Get reference to core store values
    let plugin_conf: &HashMap<String, String>;
    let state_dir: &String;
    let orig_target_args: &Vec<String>;
    unsafe {
        plugin_conf = store.as_ref(STORE_PLUGIN_CONF, Some(core))?;
        orig_target_args = store.as_ref(STORE_TARGET_ARGS, Some(core))?;
        state_dir = store.as_ref(STORE_STATE_DIR, Some(core))?;
    }

    // Parse our config values
    s.load_config(core, plugin_conf)?;

    // Create potential input file name
    let mut input_path = PathBuf::new();
    input_path.push(state_dir);
    if let Some(ref custom_fname) = s.target_input_path {
        input_path.push(custom_fname);
    } else {
        input_path.push("cur_input");
    }
    let input_path = input_path.to_str().unwrap().to_string();
    let mut target_args = Vec::with_capacity(orig_target_args.len());
    // Build arg list swapping @@ for file path
    for arg in orig_target_args {
        if "@@" == arg {
            match s.input_file {
                Some(_) => target_args.push(&input_path),
                None => {
                    target_args.push(&input_path);
                    s.input_file = Some(match File::create(&input_path) {
                        Ok(f) => f,
                        Err(e) => {
                            core.error(&format!(
                                "Failed to create input file {} : {}",
                                input_path, e
                            ));
                            return Err(From::from(
                                "Failed to create input file for target".to_string(),
                            ));
                        }
                    });
                }
            };
        } else {
            target_args.push(&arg);
        }
    }

    // set command args
    if !target_args.is_empty() {
        s.cmd.args(&target_args);
    }

    // set command working directory
    if let Some(ref target_wd) = s.target_working_dir {
        s.cmd.current_dir(target_wd);
    }

    // Set input method
    if s.input_file.is_some() {
        s.cmd.stdin(Stdio::null());
    } else {
        s.cmd.stdin(Stdio::piped());
    }

    core.info(&format!("Running '{}' {:?}", target_bin_path, target_args));

    Ok(Box::into_raw(s) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    // Make sure someone is providing us input bytes
    s.cur_input = unsafe { store.as_ref(STORE_INPUT_BYTES, Some(core))? };

    Ok(())
}

// Perform our task in the fuzzing loop
fn run_target(
    core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    // Update file on disk
    if let Some(ref mut f) = s.input_file {
        let _ = (f.set_len(0), f.seek(std::io::SeekFrom::Start(0)));
        if let Err(e) = f.write_all(&s.cur_input) {
            core.error(&format!("Failed to write target input : {}", e));
            return Err(From::from("Failed to write target input".to_string()));
        }
        let _ = f.flush();
    }

    let child_start: Instant = Instant::now();
    let mut child = match s.cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            core.error(&format!("Failed to spawn child process : {}", e));
            return Err(From::from("Failed to spawn target".to_string()));
        }
    };

    // Feed input in stdin if required
    if s.input_file.is_none() {
        let stdin = child.stdin.as_mut().unwrap();
        if let Err(e) = stdin.write_all(&s.cur_input) {
            core.error(&format!("Failed to write target stdin : {}", e));
            return Err(From::from("Failed to write target stdin".to_string()));
        }
    }

    // Wait for child
    let result = if let Some(timeout) = s.target_timeout_ms {
        child.wait_timeout(timeout).unwrap()
    } else {
        Some(child.wait().unwrap())
    };

    s.exec_time = child_start.elapsed().as_nanos() as u64;

    update_average(
        s.avg_exec_time.val,
        s.exec_time,
        *s.avg_denominator,
    );

    match result {
        None => {
            let _ = child.kill();
            s.exit_status = TargetExitStatus::Timeout
        }
        Some(ref r) => {
            match os::get_exception(&r) {
                Some(exception) => {
                    s.exit_status = TargetExitStatus::Crash(exception);
                }
                None => {
                    s.exit_status = TargetExitStatus::Normal(r.code().unwrap() as _);
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

    store.remove(STORE_EXIT_STATUS)?;
    store.remove(STORE_TARGET_EXEC_TIME)?;
    store.remove(STORE_AVG_TARGET_EXEC_TIME)?;

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
                    core.error(&format!(
                        "Failed to parse number in target_timeout_ms config '{}' : {}",
                        v, e
                    ));
                    return Err(From::from("Invalid config".to_string()));
                }
            }
        }

        if let Some(v) = conf.get("target_wd") {
            // Make sure its a valid directory
            if !Path::new(v.as_str()).is_dir() {
                core.error(&format!("Target working directory does not exist '{}'", v));
                return Err(From::from("Invalid config".to_string()));
            }
            self.target_working_dir = Some(v.clone());
        }
        Ok(())
    }
}
