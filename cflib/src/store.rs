use std::collections::HashMap;

use crate::*;

pub type CfStore = HashMap<String, *mut u8>;
pub trait CfStoreUtil {
    /// Inserts this reference casted to a raw pointer into the store.
    fn insert_exclusive<T>(
        &mut self,
        key: &str,
        val: &T,
        core: Option<&mut dyn PluginInterface>,
    ) -> Result<()>;

    /// Casts the value of this store's key entry to &T
    /// # Safety
    /// This function cannot validate any information about the store's values.
    /// Casting to the wrong T and bad assumptions about the lifetime of this reference will result in issues.
    unsafe fn as_ref<T>(
        &self,
        key: &str,
        core: Option<&mut dyn PluginInterface>,
    ) -> Result<&'static T>;

    /// Casts the value of this store's key entry to &mut T
    /// # Safety
    /// This function cannot validate any information about the store's values.
    /// Casting to the wrong T and bad assumptions about the lifetime of this reference will result in issues.
    unsafe fn as_mutref<T>(
        &mut self,
        key: &str,
        core: Option<&mut dyn PluginInterface>,
    ) -> Result<&'static mut T>;

    /// Calls as_mutref() and if it fails, inserts the provided value instead.
    /// # Safety
    /// This function cannot validate any information about the store's values.
    /// Casting to the wrong T and bad assumptions about the lifetime of this reference will result in issues.
    unsafe fn as_mutref_or_insert<T>(
        &mut self,
        key: &str,
        val: &mut T,
        core: Option<&mut dyn PluginInterface>,
    ) -> Result<(&'static mut T, bool)>;
}

/* Values managed by the core */
/// (*const String) Input directory for starting testcases
pub const STORE_INPUT_DIR: &str = "input_dir";
/// (*const String) state directory for any fuzzer/plugin state
pub const STORE_STATE_DIR: &str = "state_dir";
/// (*const String) result directory for any interesting findings
pub const STORE_RESULTS_DIR: &str = "results_dir";
/// (*const String) path of the target binary being fuzzed
pub const STORE_TARGET_BIN: &str = "target_bin";
/// (*const Vec<String>) List of arguments passed to the target
pub const STORE_TARGET_ARGS: &str = "target_args";
/// (*const String) Current working directory
pub const STORE_CWD: &str = "cwd";
/// (*const String) Name of the current fuzzer
pub const STORE_FUZZER_NAME: &str = "fuzzer_name";
/// (*const usize) Instance number of the current fuzzer
pub const STORE_FUZZER_ID: &str = "fuzzer_id";
/// (*const HashMap<String, String>) Map of arbitrary plugin configs
pub const STORE_PLUGIN_CONF: &str = "plugin_conf";
/// (*const u64) Number of values in the current rolling average calculations
pub const STORE_AVG_DENOMINATOR: &str = "avg_denominator";
/// (*const u64) Number of target executions / iterations
pub const STORE_NUM_EXECS: &str = "num_execs";
/// (*mut bool) Whether mutation plugins should run or not
pub const STORE_NO_MUTATE: &str = "no_mutate";
/// (*mut bool) Whether select plugins should run or not
pub const STORE_NO_SELECT: &str = "no_select";
/// (*const CoreState) Whether select plugins should run or not
pub const STORE_CORE_STATE: &str = "core_state";

/* Other popular keys */

/* Corpus management */
/// (*mut Vec<CfInputInfo>) Current list of possible inputs
pub const STORE_INPUT_LIST: &str = "input_list";
/// (*mut Vec<&CfNewInput) New inputs that should be saved/tracked
pub const STORE_NEW_INPUTS: &str = "new_inputs";

/* Input selection & mutation */
/// (*const usize) Index of the select input in INPUT_LIST
pub const STORE_INPUT_IDX: &str = "input_idx";
/// (*mut CfInput) Contents of the selected input
pub const STORE_INPUT_BYTES: &str = "input_bytes";
/// (*mut bool) Whether someone wants us to re-select the same input
pub const STORE_RESTORE_INPUT: &str = "restore_input";
/// (*mut BinaryHeap<InputPriority>) Holds a priority queue of input indexes
pub const STORE_INPUT_PRIORITY: &str = "input_priority";

/* Target exec */
/// (*mut TargetExitStatus) The exit status for the last run
pub const STORE_EXIT_STATUS: &str = "exit_status";
/// (*const u64) Number of nanoseconds the target took to run the last input
pub const STORE_TARGET_EXEC_TIME: &str = "exec_time";
/// (*const u64) Average nanoseconds the target takes to run
pub const STORE_AVG_TARGET_EXEC_TIME: &str = "avg_exec_time";

pub enum TargetExitStatus {
    Normal(i32),
    Timeout,
    Crash(i32),
}

fn get_valid_ptr(store: &CfStore, key: &str) -> Result<*mut u8> {
    if let Some(v) = store.get(key) {
        if v.is_null() {
            Err(From::from("Store pointer is null".to_string()))
        } else {
            Ok(*v)
        }
    } else {
        Err(From::from("Store key is missing".to_string()))
    }
}

impl CfStoreUtil for CfStore {
    fn insert_exclusive<T>(
        &mut self,
        key: &str,
        val: &T,
        core: Option<&mut dyn PluginInterface>,
    ) -> Result<()> {
        if self.get(key).is_some() {
            if let Some(ref core) = core {
                core.error(&format!("Another plugin already created {} !", key));
            }

            return Err(From::from("Plugin store conflict".to_string()));
        }
        self.insert(key.to_string(), val as *const T as *mut u8);

        Ok(())
    }
    unsafe fn as_ref<T>(
        &self,
        key: &str,
        core: Option<&mut dyn PluginInterface>,
    ) -> Result<&'static T> {
        match get_valid_ptr(self, key) {
            Err(e) => {
                if let Some(core) = &core {
                    core.error(&format!("Failed to get mandatory store value {} !", key));
                }
                Err(e)
            }
            Ok(raw_ptr) => Ok(&*(raw_ptr as *mut T as *const T)),
        }
    }
    unsafe fn as_mutref<T>(
        &mut self,
        key: &str,
        core: Option<&mut dyn PluginInterface>,
    ) -> Result<&'static mut T> {
        match get_valid_ptr(self, key) {
            Err(e) => {
                if let Some(ref core) = core {
                    core.error(&format!("Failed to get mandatory store value {} !", key));
                }
                Err(e)
            }
            Ok(raw_ptr) => Ok(&mut *(raw_ptr as *mut T)),
        }
    }
    unsafe fn as_mutref_or_insert<T>(
        &mut self,
        key: &str,
        val: &mut T,
        core: Option<&mut dyn PluginInterface>,
    ) -> Result<(&'static mut T, bool)> {
        match self.as_mutref(key, None) {
            Ok(v) => Ok((v, false)),
            Err(_) => {
                self.insert_exclusive(key, val, None)?;
                match self.as_mutref(key, core) {
                    Ok(v) => Ok((v, true)),
                    Err(e) => Err(e),
                }
            }
        }
    }
}
