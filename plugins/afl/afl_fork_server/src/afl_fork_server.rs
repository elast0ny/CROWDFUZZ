use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::fs::File;
use std::io::{Seek, Write};
use std::time::{Duration, Instant};

use ::afl_lib::*;
use ::cflib::*;

::cfg_if::cfg_if! {
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

pub struct State {
    pub afl: &'static mut AflGlobals,
    ctx: os::State,

    pub target_bin: &'static String,
    pub target_args: Vec<String>,
    pub exit_status: TargetExitStatus,
    pub input_file: Option<File>,
    pub exec_time: u64,
    pub target_input_path: Option<String>,
    pub target_working_dir: Option<String>,
    pub target_timeout_ms: Option<Duration>,
    pub avg_exec_time: StatNum,
    pub avg_denominator: &'static u64,
    pub cur_input: &'static CfInput,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {

    #[allow(invalid_value)]
    let mut s = Box::new(unsafe {
        State {
            // Plugin store vals
            afl: MaybeUninit::zeroed().assume_init(),
            ctx: MaybeUninit::zeroed().assume_init(),

            exit_status: TargetExitStatus::Normal(0),
            input_file: None,
            exec_time: 0,
            target_input_path: None,
            target_working_dir: None,
            target_timeout_ms: None,
            target_args: Vec::new(),
            
            // Stats
            avg_exec_time: core.new_stat_num(STAT_TARGET_EXEC_TIME, 0)?,
            // Core store values
            avg_denominator: store.as_ref(STORE_AVG_DENOMINATOR, Some(core))?,
            target_bin: store.as_ref(STORE_TARGET_BIN, Some(core))?,
            // Plugin store values
            cur_input: MaybeUninit::zeroed().assume_init(),
        }
    });

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
    let input_path = input_path.to_str().unwrap();
    s.target_args = Vec::with_capacity(orig_target_args.len());
    // Build arg list swapping @@ for file path
    for arg in orig_target_args {
        if "@@" == arg {
            match s.input_file {
                Some(_) => s.target_args.push(input_path.to_string()),
                None => {
                    s.target_args.push(input_path.to_string());
                    s.input_file = Some(match File::create(input_path) {
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
            s.target_args.push(arg.to_string());
        }
    }

    Ok(Box::into_raw(s) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    unsafe {
        s.afl = store.as_mutref(STORE_AFL_GLOBALS, Some(core))?;
        // Make sure someone is providing us input bytes
        s.cur_input = store.as_ref(STORE_INPUT_BYTES, Some(core))?;
    }

    s.ctx = os::State::new(s, core, store)?;

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
    
    s.exit_status = os::run_target(s)?;
    
    s.exec_time = child_start.elapsed().as_nanos() as u64;
    update_average(
        s.avg_exec_time.val,
        s.exec_time,
        *s.avg_denominator,
    );

    Ok(())
}

// Unload and free our resources
fn destroy(
    _core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let _state = box_take!(plugin_ctx, State);

    store.remove(STORE_EXIT_STATUS).unwrap();
    store.remove(STORE_TARGET_EXEC_TIME).unwrap();
    store.remove(STORE_AVG_TARGET_EXEC_TIME).unwrap();

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