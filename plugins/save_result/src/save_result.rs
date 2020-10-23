use std::collections::HashMap;
use std::fs::{self, File};
use std::io::prelude::*;
use std::mem::MaybeUninit;
use std::path::PathBuf;

use ::cflib::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, save_result);
cflib::register!(unload, destroy);

struct State {
    /// Reference to the currently selected input
    exit_status: &'static TargetExitStatus,
    cur_input: &'static mut CfInput,
    cur_input_idx: &'static usize,
    input_list: &'static mut Vec<CfInputInfo>,

    tmp_str: String,
    crash_dir: PathBuf,
    timeout_dir: PathBuf,
    num_crashes: StatNum,
    num_timeouts: StatNum,
    stat_crash_dir: StatStr,
    state_timeout_dir: StatStr,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let mut state = Box::new(unsafe {
        State {
            exit_status: MaybeUninit::zeroed().assume_init(),
            cur_input: MaybeUninit::zeroed().assume_init(),
            input_list: MaybeUninit::zeroed().assume_init(),
            cur_input_idx: MaybeUninit::zeroed().assume_init(),

            tmp_str: String::with_capacity(40),
            crash_dir: PathBuf::new(),
            timeout_dir: PathBuf::new(),
            num_crashes: match core
                .add_stat(&format!("{}crashes", TAG_PREFIX_TOTAL), NewStat::Num(0))
            {
                Ok(StatVal::Num(v)) => v,
                _ => return Err(From::from("Failed to reserve stat".to_string())),
            },
            num_timeouts: match core
                .add_stat(&format!("{}timeouts", TAG_PREFIX_TOTAL), NewStat::Num(0))
            {
                Ok(StatVal::Num(v)) => v,
                _ => return Err(From::from("Failed to reserve stat".to_string())),
            },
            stat_crash_dir: MaybeUninit::zeroed().assume_init(),
            state_timeout_dir: MaybeUninit::zeroed().assume_init(),
        }
    });

    let plugin_conf = raw_to_ref!(*store.get(STORE_PLUGIN_CONF).unwrap(), HashMap<String, String>);
    let state_dir = raw_to_ref!(*store.get(STORE_STATE_DIR).unwrap(), String);

    // Create crashes dir
    state.crash_dir.push(state_dir);
    if let Some(p) = plugin_conf.get("crashes_dir") {
        state.crash_dir.push(p);
    } else {
        state.crash_dir.push("crashes");
    }
    if !state.crash_dir.is_dir() {
        if let Err(e) = fs::create_dir_all(&state.crash_dir) {
            core.log(
                LogLevel::Error,
                &format!(
                    "Failed to create crashes directory {} : {}",
                    state.crash_dir.to_string_lossy(),
                    e
                ),
            );
            return Err(From::from(e));
        };
    }
    let tmp: &str = state.crash_dir.to_str().unwrap();
    state.stat_crash_dir = match core.add_stat(
        &format!("crashes_dir{}", TAG_POSTFIX_PATH),
        NewStat::Str {
            max_size: tmp.len(),
            init_val: tmp,
        },
    ) {
        Ok(StatVal::Str(v)) => v,
        _ => return Err(From::from("Failed to reserve stat".to_string())),
    };

    // Create timeouts dir
    state.timeout_dir.push(state_dir);
    if let Some(p) = plugin_conf.get("timeouts_dir") {
        state.timeout_dir.push(p);
    } else {
        state.timeout_dir.push("timeouts");
    }
    if !state.timeout_dir.is_dir() {
        if let Err(e) = fs::create_dir_all(&state.timeout_dir) {
            core.log(
                LogLevel::Error,
                &format!(
                    "Failed to create timeouts directory {} : {}",
                    state.timeout_dir.to_string_lossy(),
                    e
                ),
            );
            return Err(From::from(e));
        };
    }
    let tmp: &str = state.timeout_dir.to_str().unwrap();
    state.state_timeout_dir = match core.add_stat(
        &format!("timeouts_dir{}", TAG_POSTFIX_PATH),
        NewStat::Str {
            max_size: tmp.len(),
            init_val: tmp,
        },
    ) {
        Ok(StatVal::Str(v)) => v,
        _ => return Err(From::from("Failed to reserve stat".to_string())),
    };

    Ok(Box::into_raw(state) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // We need a plugin that creates in exit_status
    if let Some(v) = store.get(STORE_EXIT_STATUS) {
        state.exit_status = raw_to_ref!(*v, TargetExitStatus);
    } else {
        core.log(LogLevel::Error, "No plugin created exit_status !");
        return Err(From::from("No exit_status".to_string()));
    }

    // We need a plugin that creates in input_bytes
    if let Some(v) = store.get(STORE_INPUT_BYTES) {
        state.cur_input = raw_to_mutref!(*v, CfInput);
    } else {
        core.log(LogLevel::Error, "No plugin created input_bytes !");
        return Err(From::from("No selected input".to_string()));
    }

    if let Some(v) = store.get(STORE_INPUT_IDX) {
        state.cur_input_idx = raw_to_mutref!(*v, usize);
    } else {
        core.log(LogLevel::Error, "No plugin created input_idx !");
        return Err(From::from("No selected input".to_string()));
    }

    match store.get(STORE_INPUT_LIST) {
        Some(v) => state.input_list = raw_to_mutref!(*v, Vec<CfInputInfo>),
        None => {
            core.log(LogLevel::Error, "No plugin managing input_list !");
            return Err(From::from("No inputs".to_string()));
        }
    };

    Ok(())
}

// Perform our task in the fuzzing loop
fn save_result(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Save input if interesting exit_status
    state.save_input()?;

    Ok(())
}

// Unload and free our resources
fn destroy(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let _state = box_take!(plugin_ctx, State);
    Ok(())
}

impl State {
    /// Saves the current input if exit_status was interesting
    pub fn save_input(&mut self) -> Result<bool> {
        let dst: &mut PathBuf = match self.exit_status {
            TargetExitStatus::Crash(_) => {
                *self.num_crashes.val += 1;
                &mut self.crash_dir
            }
            TargetExitStatus::Timeout => {
                *self.num_timeouts.val += 1;
                &mut self.crash_dir
            }
            _ => return Ok(false),
        };

        let input_info = unsafe { self.input_list.get_unchecked(*self.cur_input_idx) };

        // Build hexstr from file uid
        self.tmp_str.clear();
        for b in &input_info.uid {
            use std::fmt::Write;
            let _ = write!(&mut self.tmp_str, "{:02X}", *b);
        }

        // Create out file
        dst.push(&self.tmp_str);
        let mut file = match File::create(&dst) {
            Ok(f) => f,
            Err(e) => {
                let _ = dst.pop();
                return Err(From::from(e));
            }
        };
        let _ = dst.pop();

        // Write file contents
        for chunk in &self.cur_input.chunks {
            if let Err(e) = file.write_all(chunk) {
                let _ = fs::remove_file(&dst);
                return Err(From::from(e));
            }
        }
        Ok(true)
    }
}
