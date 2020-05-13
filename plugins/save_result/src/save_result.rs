use std::collections::HashSet;
use std::ffi::c_void;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::slice::from_raw_parts;

use crypto::digest::Digest;
use crypto::sha1::Sha1;

use cflib::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(init, init);
cflib::register!(validate, validate);
cflib::register!(work, post_run);
cflib::register!(destroy, destroy);

struct State {
    store: Store,
    stats: Stats,
    crash_dir: PathBuf,
    timeout_dir: PathBuf,

    cur_hash: [u8; 20],
    hasher: Sha1,
    unique_files: HashSet<[u8; 20]>,
}

extern "C" fn init(core_ptr: *mut CoreInterface) -> PluginStatus {
    let core = cflib::cast!(core_ptr);

    let mut state = Box::new(State {
        store: Store::default(),
        stats: Stats::default(),
        crash_dir: PathBuf::new(),
        timeout_dir: PathBuf::new(),

        cur_hash: [0; 20],
        hasher: Sha1::new(),
        unique_files: HashSet::new(),
    });

    // Allocate space for our statistics
    state.stats.existing_crashes = unsafe {
        &mut *(core
            .add_stat(
                &format!("{}existing_crashes", cflib::TAG_PREFIX_TOTAL_STR),
                NewStat::Number,
            )
            .unwrap() as *mut _)
    };
    *state.stats.existing_crashes = 0;
    state.stats.existing_timeouts = unsafe {
        &mut *(core
            .add_stat(
                &format!("{}existing_timeouts", cflib::TAG_PREFIX_TOTAL_STR),
                NewStat::Number,
            )
            .unwrap() as *mut _)
    };
    *state.stats.existing_timeouts = 0;
    state.stats.new_crashes = unsafe {
        &mut *(core
            .add_stat(
                &format!("{}new_crashes", cflib::TAG_PREFIX_TOTAL_STR),
                NewStat::Number,
            )
            .unwrap() as *mut _)
    };
    *state.stats.new_crashes = 0;
    state.stats.new_timeouts = unsafe {
        &mut *(core
            .add_stat(
                &format!("{}new_timeouts", cflib::TAG_PREFIX_TOTAL_STR),
                NewStat::Number,
            )
            .unwrap() as *mut _)
    };
    *state.stats.new_timeouts = 0;

    core.priv_data = Box::into_raw(state) as *mut _;

    STATUS_SUCCESS
}

extern "C" fn validate(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let (core, state) = cflib::cast!(core_ptr, priv_data, State);

    // Extract values we need from the store
    state.store.exit_status =
        cflib::store_get_ref!(mandatory, CFTuple, core, KEY_EXIT_STATUS_STR, 0);
    state.store.result_dir = cflib::store_get_ref!(mandatory, CFUtf8, core, KEY_RESULT_DIR_STR, 0);
    state.store.cur_input =
        cflib::store_get_ref!(mandatory, CFVec, core, KEY_CUR_INPUT_CHUNKS_STR, 0);
    state.store.exec_only =
        cflib::store_get_ref!(mandatory, CFBool, core, KEY_ONLY_EXEC_MODE_STR, 0);

    state.crash_dir = PathBuf::from(state.store.result_dir.as_utf8());
    state.timeout_dir = state.crash_dir.clone();

    state.crash_dir.push("crashes/");
    state.timeout_dir.push("timeouts/");

    // Create directories
    for d in [&state.crash_dir, &state.timeout_dir].iter() {
        if let Err(e) = std::fs::create_dir_all(d) {
            core.log(
                LOGLEVEL_ERROR,
                &format!(
                    "Failed to create directory '{}' : {}",
                    d.to_string_lossy(),
                    e
                ),
            );
            return STATUS_PLUGINERROR;
        }
    }

    core.log(
        LOGLEVEL_INFO,
        &format!("Writing crashes to '{}'", state.crash_dir.to_string_lossy()),
    );
    core.log(
        LOGLEVEL_INFO,
        &format!(
            "Writing timeouts to '{}'",
            state.timeout_dir.to_string_lossy()
        ),
    );

    // Ingest any existing files
    state.scrape_existing_dirs();

    // Pre-allocate space for filename
    state.crash_dir.push("dummyfilename0123456");
    state.timeout_dir.push("dummyfilename0123456");

    STATUS_SUCCESS
}

extern "C" fn destroy(_core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    // Free our state data
    let _state: Box<State> = unsafe { Box::from_raw(priv_data as *mut _) };

    STATUS_SUCCESS
}

///Select random byte in input and assign random value to it
extern "C" fn post_run(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let (core, state) = cflib::cast!(core_ptr, priv_data, State);

    // Ignore if exec_only or if not a crash or timeout
    if *state.store.exec_only == CF_TRUE
        || (state.store.exit_status.first != EXIT_STATUS_CRASH as _
            && state.store.exit_status.first != EXIT_STATUS_TIMEOUT as _)
    {
        return STATUS_SUCCESS;
    }

    // Compute the hash of the input
    state.hasher.reset();
    let chunks: &[CFBuf] = state.store.cur_input.as_slice();
    for chunk in chunks.iter() {
        state
            .hasher
            .input(unsafe { from_raw_parts(chunk.buf, chunk.len) });
    }
    state.hasher.result(&mut state.cur_hash);

    // Already seen this input
    if state.unique_files.contains(&state.cur_hash) {
        return STATUS_SUCCESS;
    }

    let out_file = if state.store.exit_status.first == EXIT_STATUS_CRASH as _ {
        *state.stats.new_crashes += 1;
        state.crash_dir.set_file_name(format!(
            "0x{:X}_{}",
            state.store.exit_status.second,
            state.hasher.result_str()
        ));
        state.crash_dir.as_path()
    } else {
        *state.stats.new_timeouts += 1;
        state.timeout_dir.set_file_name(state.hasher.result_str());
        state.timeout_dir.as_path()
    };

    // Create file
    let mut f = match File::create(out_file) {
        Ok(f) => f,
        Err(e) => {
            core.log(
                LOGLEVEL_ERROR,
                &format!(
                    "Failed to create new file '{}' : {}",
                    out_file.to_string_lossy(),
                    e
                ),
            );
            return STATUS_PLUGINERROR;
        }
    };

    //Write chunks to disk
    for chunk in chunks {
        if let Err(e) = f.write_all(unsafe { from_raw_parts(chunk.buf, chunk.len) }) {
            core.log(LOGLEVEL_ERROR, &format!("Failed to write : {}", e));
            return STATUS_PLUGINERROR;
        }
    }

    STATUS_SUCCESS
}

struct Store {
    // Borrowed values
    pub result_dir: &'static CFUtf8,
    pub exit_status: &'static CFTuple,
    pub cur_input: &'static CFVec,
    pub exec_only: &'static CFBool,
}
impl Default for Store {
    fn default() -> Self {
        unsafe {
            Self {
                result_dir: &*null(),
                exit_status: &*null(),
                cur_input: &*null(),
                exec_only: &*null(),
            }
        }
    }
}

struct Stats {
    pub existing_crashes: &'static mut u64,
    pub existing_timeouts: &'static mut u64,
    pub new_crashes: &'static mut u64,
    pub new_timeouts: &'static mut u64,
}
impl Default for Stats {
    fn default() -> Self {
        unsafe {
            Self {
                existing_crashes: &mut *null_mut(),
                existing_timeouts: &mut *null_mut(),
                new_crashes: &mut *null_mut(),
                new_timeouts: &mut *null_mut(),
            }
        }
    }
}

impl State {
    pub fn scrape_existing_dirs(&mut self) {
        let mut existing_file_list = Vec::new();

        // Get all existing files
        for (idx, d) in [&self.crash_dir, &self.timeout_dir].iter().enumerate() {
            let dir_listing = match fs::read_dir(d) {
                Ok(v) => v,
                _ => continue,
            };

            for entry in dir_listing {
                let (entry, info) = match entry {
                    Ok(e) => {
                        let info = match e.metadata() {
                            Ok(v) => v,
                            _ => continue,
                        };
                        (e, info)
                    }
                    _ => continue,
                };

                //Skip directories
                if !info.is_file() {
                    continue;
                }

                if idx == 0 {
                    *self.stats.existing_crashes += 1;
                } else {
                    *self.stats.existing_timeouts += 1;
                }

                existing_file_list.push(entry.path());
            }
        }

        // For every detected file, compute their hash
        let mut file_contents = Vec::new();
        for file in &existing_file_list {
            let mut f = match File::open(file) {
                Ok(v) => v,
                Err(_e) => continue, // Failed to open
            };
            match f.read_to_end(&mut file_contents) {
                Ok(_) => {}
                Err(_e) => continue, // Failed to read
            }

            // Compute hash
            self.hasher.reset();
            self.hasher.input(&file_contents);
            self.hasher.result(&mut self.cur_hash);

            self.unique_files.insert(self.cur_hash);
        }
    }
}
