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
    cur_input: &'static CfInput,
    cur_input_idx: &'static usize,
    input_list: &'static Vec<CfInputInfo>,

    tmp_str: String,
    crash_dir: PathBuf,
    timeout_dir: PathBuf,
    num_crashes: StatNum,
    num_timeouts: StatNum,
    stat_crash_dir: StatStr,
    stat_timeout_dir: StatStr,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let mut state = Box::new(unsafe {
        State {
            tmp_str: String::with_capacity(40),
            crash_dir: PathBuf::new(),
            timeout_dir: PathBuf::new(),

            // Stats
            num_crashes: core.new_stat_num(&format!("{}crashes", TAG_PREFIX_TOTAL), 0)?,
            num_timeouts: core.new_stat_num(&format!("{}timeouts", TAG_PREFIX_TOTAL), 0)?,
            stat_crash_dir: MaybeUninit::zeroed().assume_init(),
            stat_timeout_dir: MaybeUninit::zeroed().assume_init(),

            // Plugin store values
            exit_status: MaybeUninit::zeroed().assume_init(),
            cur_input: MaybeUninit::zeroed().assume_init(),
            input_list: MaybeUninit::zeroed().assume_init(),
            cur_input_idx: MaybeUninit::zeroed().assume_init(),
        }
    });

    let plugin_conf: &HashMap<String, String>;
    let state_dir: &String;
    // Get core store values
    unsafe {
        plugin_conf = store.as_ref(STORE_PLUGIN_CONF, Some(core))?;
        state_dir = store.as_ref(STORE_STATE_DIR, Some(core))?;
    }

    // Create crashes dir
    state.crash_dir.push(state_dir);
    if let Some(p) = plugin_conf.get("crashes_dir") {
        state.crash_dir.push(p);
    } else {
        state.crash_dir.push("crashes");
    }
    if !state.crash_dir.is_dir() {
        if let Err(e) = fs::create_dir_all(&state.crash_dir) {
            core.error(&format!(
                "Failed to create crashes directory {} : {}",
                state.crash_dir.to_string_lossy(),
                e
            ));
            return Err(From::from(e));
        };
    }
    // Add crash_dir to stats
    let tmp: &str = state.crash_dir.to_str().unwrap();
    state.stat_crash_dir =
        core.new_stat_str(&format!("crashes_dir{}", TAG_POSTFIX_PATH), tmp.len(), tmp)?;

    // Create timeouts dir
    state.timeout_dir.push(state_dir);
    if let Some(p) = plugin_conf.get("timeouts_dir") {
        state.timeout_dir.push(p);
    } else {
        state.timeout_dir.push("timeouts");
    }
    if !state.timeout_dir.is_dir() {
        if let Err(e) = fs::create_dir_all(&state.timeout_dir) {
            core.error(&format!(
                "Failed to create timeouts directory {} : {}",
                state.timeout_dir.to_string_lossy(),
                e
            ));
            return Err(From::from(e));
        };
    }
    // Add timeout_dir to stats
    let tmp: &str = state.timeout_dir.to_str().unwrap();
    state.stat_timeout_dir =
        core.new_stat_str(&format!("timeouts_dir{}", TAG_POSTFIX_PATH), tmp.len(), tmp)?;

    Ok(Box::into_raw(state) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Get all the plugin store values we need
    unsafe {
        state.exit_status = store.as_ref(STORE_EXIT_STATUS, Some(core))?;
        state.cur_input = store.as_ref(STORE_INPUT_BYTES, Some(core))?;
        state.cur_input_idx = store.as_ref(STORE_INPUT_IDX, Some(core))?;
        state.input_list = store.as_ref(STORE_INPUT_LIST, Some(core))?;
    }

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
        
        // Likely path first 
        if let TargetExitStatus::Normal(_) = self.exit_status {
            return Ok(false);
        }

        let dst: &mut PathBuf = match self.exit_status {
            TargetExitStatus::Crash(_) => {
                *self.num_crashes.val += 1;
                &mut self.crash_dir
            }
            TargetExitStatus::Timeout => {
                *self.num_timeouts.val += 1;
                &mut self.crash_dir
            }
            TargetExitStatus::Normal(_) => unreachable!(),
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
