use std::collections::HashMap;
use std::path::PathBuf;

pub type CfStore = HashMap<String, *mut u8>;

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
/// (*const String) ID of the current fuzzer
pub const STORE_FUZZER_ID: &str = "fuzzer_id";
/// (*const HashMap<String, String>) Map of arbitrary plugin configs
pub const STORE_PLUGIN_CONF: &str = "plugin_conf";
/// (*const u64) Number of values in the current rolling average calculations
pub const STORE_AVG_DENOMINATOR: &str = "avg_denominator";
/// (*const u64) Number of target executions / iterations
pub const STORE_NUM_EXECS: &str = "num_execs";
/// (*mut bool) Whether mutation plugins should mutate or not
pub const STORE_NO_MUTATE: &str = "no_mutate";

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


/* Target exec */
/// (*mut u64) The number of US for the last run
pub const STORE_TARGET_EXEC_SPEED: &str = "target_exec_us";
/// (*mut TargetExitStatus) The exit status for the last run
pub const STORE_EXIT_STATUS: &str = "exit_status";

pub enum TargetExitStatus {
    Normal,
    Timeout,
    Crash(i32),
}

/// Represents generic info for a specific input
pub struct CfInputInfo {
    /// A unique identifier for this file
    pub uid: Vec<u8>,
    /// Contents of the input
    pub contents: Option<CfInput>,
    /// Path to the input if it is on disk
    pub path: Option<PathBuf>,
}

/// Represents the contents of an input
pub struct CfInput {
    /// List of chunks representing the input
    pub chunks: Vec<&'static mut [u8]>,
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
