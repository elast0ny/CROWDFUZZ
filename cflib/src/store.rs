use std::collections::HashMap;
use std::path::PathBuf;

pub type CfStore = HashMap<String, *mut u8>;

/* Values managed by the core */
/// (&String) Input directory for starting testcases
pub const STORE_INPUT_DIR: &str = "input_dir";
/// (&String) state directory for any fuzzer/plugin state
pub const STORE_STATE_DIR: &str = "state_dir";
/// (&String) result directory for any interesting findings
pub const STORE_RESULTS_DIR: &str = "results_dir";
/// (&String) path of the target binary being fuzzed
pub const STORE_TARGET_BIN: &str = "target_bin";
/// (&Vec<String>) List of arguments passed to the target
pub const STORE_TARGET_ARGS: &str = "target_args";
/// (&String) Current working directory
pub const STORE_CWD: &str = "cwd";
/// (&String) ID of the current fuzzer
pub const STORE_FUZZER_ID: &str = "fuzzer_id";
/// (&HashMap<String, String>) Map of arbitrary plugin configs
pub const STORE_PLUGIN_CONF: &str = "plugin_conf";
/// (&u64) Number of values in the current rolling average calculations
pub const STORE_AVG_DENOMINATOR: &str = "avg_denominator";
/// (&u64) Number of target executions / iterations
pub const STORE_NUM_EXECS: &str = "num_execs";
/// (&mut bool) Whether mutation plugins should mutate or not
pub const STORE_NO_MUTATE: &str = "no_mutate";

/* Other popular keys */

/* Corpus management */
/// (&mut Vec<CfInputInfo>) Current list of possible inputs
pub const STORE_INPUT_LIST: &str = "input_list";
/// (&mut Vec<&CfNewInput) New inputs that should be saved/tracked
pub const STORE_NEW_INPUTS: &str = "new_inputs";

/* Input selection */
/// (&mut CfInput) Index of the select input in INPUT_LIST
pub const STORE_INPUT_IDX: &str = "input_idx";
/// (&mut CfInput) Contents of the selected input
pub const STORE_INPUT_BYTES: &str = "input_bytes";

/* Input mutation */
/// (&mut CfInput) Contents of the mutated input
pub const STORE_MUTATED_INPUT_BYTES: &str = "minput_bytes";

/* Target exec */
/// (&mut u64) The number of US for the last run
pub const STORE_TARGET_EXEC_SPEED: &str = "target_exec_us";
/// (&mut TargetExitStatus) The exit status for the last run
pub const STORE_EXIT_STATUS: &str = "exit_status";

pub enum TargetExitStatus {
    Normal,
    Timeout,
    Crash(i32),
}

/// Represents generic info for a specific input
pub struct CfInputInfo {
    /// A unique identifier for this file
    pub uid: CfBuf,
    /// Path to the input
    pub path: Option<PathBuf>,
}

pub struct CfBuf {
    pub ptr: *mut u8,
    pub len: usize,
}
impl CfBuf {
    /// # Safety
    /// This function does no checks on the validity of ptr and len
    pub unsafe fn to_slice(&self) -> &[u8] {
        std::slice::from_raw_parts_mut(self.ptr, self.len)
    }

    pub fn from_slice(s: &mut [u8]) -> Self {
        Self {
            ptr: s.as_mut_ptr(),
            len: s.len(),
        }
    }
}

/// Represents the contents of an input
pub struct CfInput {
    /// List of chunks representing the input
    pub chunks: Vec<CfBuf>,
}
impl Default for CfInput {
    fn default() -> Self {
        Self { chunks: Vec::new() }
    }
}

/// Represents generic info for a specific input
pub struct CfNewInput {
    /// Contents of the input
    pub contents: Option<*const CfInput>,
    /// Path to the input
    pub path: Option<PathBuf>,
}
