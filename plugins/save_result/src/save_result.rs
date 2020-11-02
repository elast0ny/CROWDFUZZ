use std::collections::HashMap;
use std::fs::{self, File};
use std::io::prelude::*;
use std::mem::MaybeUninit;
use std::path::PathBuf;

use ::cflib::*;
use ::crypto::{digest::Digest, sha1::Sha1};

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, save_result);
cflib::register!(unload, destroy);

struct State {
    hasher: Sha1,
    tmp_uid: [u8; 20],

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
    let mut s = Box::new(unsafe {
        State {
            hasher: Sha1::new(),
            tmp_uid: [0; 20],
            tmp_str: String::with_capacity(40),
            crash_dir: PathBuf::new(),
            timeout_dir: PathBuf::new(),

            // Stats
            num_crashes: MaybeUninit::zeroed().assume_init(),
            num_timeouts: MaybeUninit::zeroed().assume_init(),
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
    s.crash_dir.push(state_dir);
    if let Some(p) = plugin_conf.get("crashes_dir") {
        s.crash_dir.push(p);
    } else {
        s.crash_dir.push("crashes");
    }
    if !s.crash_dir.is_dir() {
        if let Err(e) = fs::create_dir_all(&s.crash_dir) {
            core.error(&format!(
                "Failed to create crashes directory {} : {}",
                s.crash_dir.to_string_lossy(),
                e
            ));
            return Err(From::from(e));
        };
    }
    // Add crash_dir to stats
    let tmp: &str = s.crash_dir.to_str().unwrap();
    s.stat_crash_dir =
        core.new_stat_str(&format!("crashes_dir{}", TAG_POSTFIX_PATH), tmp.len(), tmp)?;

    // Create timeouts dir
    s.timeout_dir.push(state_dir);
    if let Some(p) = plugin_conf.get("timeouts_dir") {
        s.timeout_dir.push(p);
    } else {
        s.timeout_dir.push("timeouts");
    }
    if !s.timeout_dir.is_dir() {
        if let Err(e) = fs::create_dir_all(&s.timeout_dir) {
            core.error(&format!(
                "Failed to create timeouts directory {} : {}",
                s.timeout_dir.to_string_lossy(),
                e
            ));
            return Err(From::from(e));
        };
    }
    // Add timeout_dir to stats
    let tmp: &str = s.timeout_dir.to_str().unwrap();
    s.stat_timeout_dir =
        core.new_stat_str(&format!("timeouts_dir{}", TAG_POSTFIX_PATH), tmp.len(), tmp)?;

    s.num_crashes = core.new_stat_num(STAT_NUM_CRASHES, 0)?;
    s.num_timeouts = core.new_stat_num(STAT_NUM_TIMEOUTS, 0)?;

    Ok(Box::into_raw(s) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    // Get all the plugin store values we need
    unsafe {
        s.exit_status = store.as_ref(STORE_EXIT_STATUS, Some(core))?;
        s.cur_input = store.as_ref(STORE_INPUT_BYTES, Some(core))?;
        s.cur_input_idx = store.as_ref(STORE_INPUT_IDX, Some(core))?;
        s.input_list = store.as_ref(STORE_INPUT_LIST, Some(core))?;
    }

    Ok(())
}

// Perform our task in the fuzzing loop
fn save_result(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    // Save input if interesting exit_status
    s.save_input()?;

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

        // calculate sha1 of input
        self.hasher.reset();
        self.hasher.input(&self.cur_input);
        self.hasher.result(&mut self.tmp_uid);

        // Build hexstr from file uid
        self.tmp_str.clear();
        for b in &self.tmp_uid {
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
        if let Err(e) = file.write_all(&self.cur_input) {
            let _ = fs::remove_file(&dst);
            return Err(From::from(e));
        }
        
        Ok(true)
    }
}
