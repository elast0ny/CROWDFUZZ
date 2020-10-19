use std::collections::{HashMap, VecDeque};

pub type CfStore = HashMap<String, VecDeque<*mut u8>>;

/* Values managed by the core */
/// (Box<&str>) Input directory for starting testcases
pub const STORE_INPUT_DIR : &str = "input_dir";
/// (Box<&str>) state directory for any fuzzer/plugin state
pub const STORE_STATE_DIR : &str = "state_dir";
/// (Box<&str>) result directory for any interesting findings
pub const STORE_RESULTS_DIR : &str = "results_dir";
/// (Box<&str>) path of the target binary being fuzzed
pub const STORE_TARGET_BIN : &str = "target_bin";
/// (Box<&str>) List of arguments passed to the target
pub const STORE_TARGET_ARGS : &str = "target_args";
/// (Box<&str>) Current working directory
pub const STORE_CWD : &str = "cwd";
/// (Box<&str>) ID of the current fuzzer
pub const STORE_FUZZER_ID : &str = "fuzzer_id";
/// (Box<&HashMap<String, String>>) Map of arbitrary plugin configs
pub const STORE_PLUGIN_CONF : &str = "plugin_conf";
/// (&u64) Number of values in the current rolling average calculations
pub const STORE_AVG_DENOMINATOR : &str = "avg_denominator";
/// (&u64) Number of target executions / iterations
pub const STORE_NUM_EXECS : &str = "num_execs";

/* Other popular keys */

/// (&str) Filepath of the selected input
pub const STORE_INPUT_PATH : &str = "input_path";
/// (Vec<u8>) Contents of the selected input
pub const STORE_INPUT_BYTES : &str = "input";
/// (Vec<(chunk: *const u8, len: u64)>) Contents of the mutated input
pub const STORE_MUTATED_INPUT_BYTES : &str = "mut_input";
/// (bool) Whether we should keep the last mut_input
pub const STORE_SAVE_MUT_INPUT : &str = "save_mut_input";
/// (u64) The number of US for the last run
pub const STORE_TARGET_EXEC_SPEED : &str = "target_exec_us";
/// (TargetExitStatus) The exit status for the last run
pub const STORE_EXIT_STATUS : &str = "exit_status";

pub enum TargetExitStatus {
    Normal,
    Timeout,
    Crash(i32),
}