use std::collections::HashSet;
use std::ffi::c_void;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::iter::FromIterator;
use std::path::PathBuf;
use std::slice::from_raw_parts;
use std::vec::Vec;

use ::crypto::digest::Digest;
use ::crypto::sha1::Sha1;

use ::cflib::*;
use ::rand::Rng;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(init, init);
cflib::register!(validate, validate);
cflib::register!(work, select_testcase);
cflib::register!(destroy, destroy);

/// Custom stats owned by the plugin
struct CustomStats {
    initial_input_num: &'static mut usize,
    generated_input_num: &'static mut usize,
}

/// Plugin state
struct State {
    hasher: Sha1,
    unique_files: HashSet<[u8; 20]>,
    result_dir: PathBuf,
    file_list: Vec<PathBuf>,
    cur_file_idx: usize,
    cur_file: Vec<u8>,
    pub_file_path: [u8; 512],
    pub_cur_file: CFVec,
    stats: CustomStats,
    input_providers: Vec<&'static CFVec>,
}

extern "C" fn init(core_ptr: *mut CoreInterface) -> PluginStatus {
    let core = cflib::cast!(core_ptr);

    // Init our state struct
    let mut state: Box<State> = unsafe {
        Box::new(State {
            hasher: Sha1::new(),
            unique_files: HashSet::new(),
            file_list: Vec::new(),
            result_dir: PathBuf::new(),
            cur_file_idx: 0,
            cur_file: Vec::with_capacity(1),
            pub_file_path: [0; 512],
            pub_cur_file: CFVec {
                length: 0,
                capacity: 0,
                data: std::ptr::null_mut(),
            },
            stats: CustomStats {
                initial_input_num: &mut *(core.add_stat("initial_inputs", NewStat::Number).unwrap()
                    as *mut _),
                generated_input_num: &mut *(core
                    .add_stat(
                        &format!("{}generated_inputs", cflib::TAG_PREFIX_TOTAL_STR),
                        NewStat::Number,
                    )
                    .unwrap() as *mut _),
            },
            input_providers: Vec::new(),
        })
    };

    *state.stats.generated_input_num = 0;
    *state.stats.initial_input_num = 0;

    // Add values we control to the store
    core.store_push_back(KEY_INPUT_PATH_STR, state.pub_file_path.as_mut_ptr());
    core.store_push_back(KEY_INPUT_BYTES_STR, &mut state.pub_cur_file as *mut _);

    //Store our state as our private data
    core.priv_data = Box::into_raw(state) as *mut _;
    STATUS_SUCCESS
}

extern "C" fn validate(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let (core, state) = cflib::cast!(core_ptr, priv_data, State);

    // Ensure the the required keys have been created by another plugin
    let input_dir = cflib::store_get_ref!(mandatory, str, core, KEY_INPUT_DIR_STR, 0);
    let state_dir = cflib::store_get_ref!(mandatory, str, core, KEY_STATE_DIR_STR, 0);

    // Create our new input folder if required
    state.result_dir = PathBuf::from(state_dir);
    state.result_dir.push("queue/");
    if let Err(e) = std::fs::create_dir_all(&state.result_dir) {
        core.log(
            LOGLEVEL_ERROR,
            &format!(
                "Failed to create output directory '{}' : {}",
                state.result_dir.to_string_lossy(),
                e
            ),
        );
        return STATUS_PLUGINERROR;
    }
    core.log(
        LOGLEVEL_INFO,
        &format!(
            "Writing output files to '{}'",
            state.result_dir.to_string_lossy()
        ),
    );

    // Scrape the input folders to gather a file list
    if let Err(e) = state.init_from_disk(core, &[input_dir]) {
        return e;
    }
    if state.file_list.len() == 0 {
        core.log(
            LOGLEVEL_ERROR,
            "No files exist in input or output directories...",
        );
        return STATUS_PLUGINERROR;
    }
    state
        .result_dir
        .push("placeholderfilenameplaceholderfilename00");
    core.log(
        LOGLEVEL_INFO,
        &format!("Found {} file(s) to use as input(s)", state.file_list.len()),
    );

    // Check if any plugins registered as new_input providers
    let mut i = 0;
    loop {
        let cur_new_input = cflib::store_get_ref!(optional, CFVec, core, KEY_NEW_INPUT_LIST_STR, i);
        match cur_new_input {
            Some(v) => state.input_providers.push(v),
            None => break,
        };
        i += 1
    }
    if i == 0 {
        core.log(LOGLEVEL_WARN, &format!("No plugins have registered as new input providers... Input list will remain static"));
    }

    STATUS_SUCCESS
}

extern "C" fn destroy(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let core = cflib::cast!(core_ptr);

    // Clean up our values
    let _state: Box<State> = unsafe { Box::from_raw(priv_data as *mut _) };
    let _: *mut c_void = core.store_pop_front(KEY_INPUT_PATH_STR);
    let _: *mut c_void = core.store_pop_front(KEY_INPUT_BYTES_STR);

    STATUS_SUCCESS
}

extern "C" fn select_testcase(
    core_ptr: *mut CoreInterface,
    priv_data: *mut c_void,
) -> PluginStatus {
    let (core, state) = cflib::cast!(core_ptr, priv_data, State);

    // Save any new inputs to disk
    if state.input_providers.len() > 0 {
        if let Err(e) = state.save_new_inputs(core) {
            return e;
        }
    }

    // Read a randomly selected file into memory
    state.set_cur_file(rand::thread_rng().gen_range(0, state.file_list.len()));
    if let Err(e) = state.load_cur_file(core) {
        return e;
    }

    // Set current filepath
    let input_path = state.file_list[state.cur_file_idx].to_string_lossy();
    let path_bytes = input_path.as_bytes();
    state.pub_file_path[path_bytes.len()] = 0;
    state.pub_file_path[0..path_bytes.len()].copy_from_slice(path_bytes);

    // Update pointer to the new file data
    state.pub_cur_file.update_from_vec(&state.cur_file);

    STATUS_SUCCESS
}

impl State {
    pub fn set_cur_file(&mut self, idx: usize) {
        self.cur_file_idx = idx;
    }

    pub fn load_cur_file(&mut self, core: &mut CoreInterface) -> Result<(), PluginStatus> {
        let fpath = &self.file_list[self.cur_file_idx];
        let mut f = match File::open(fpath) {
            Ok(v) => v,
            Err(e) => {
                core.log(
                    LOGLEVEL_ERROR,
                    &format!(
                        "Error openning file \"{}\" : {}",
                        fpath.to_string_lossy(),
                        e
                    ),
                );
                return Err(STATUS_PLUGINERROR);
            }
        };

        self.cur_file.clear();
        if let Err(e) = f.read_to_end(&mut self.cur_file) {
            core.log(
                LOGLEVEL_ERROR,
                &format!("Error reading file \"{}\" : {}", fpath.to_string_lossy(), e),
            );
            return Err(STATUS_PLUGINERROR);
        }
        Ok(())
    }

    /// updates current state of input files from list of directories
    pub fn init_from_disk(
        &mut self,
        core: &mut CoreInterface,
        dirs: &[&str],
    ) -> Result<(), PluginStatus> {
        let cur_files: HashSet<&PathBuf> = HashSet::from_iter(self.file_list.iter());
        let mut new_files = Vec::new();
        let mut all_dirs: Vec<&str> = Vec::with_capacity(dirs.len() + 1);

        for cur_dir in dirs.iter() {
            all_dirs.push(cur_dir);
        }
        all_dirs.push(self.result_dir.to_str().unwrap());

        for cur_dir in all_dirs.iter() {
            core.log(LOGLEVEL_DEBUG, &format!("Searching '{}'", cur_dir));
            let dir_listing = match fs::read_dir(cur_dir) {
                Ok(v) => v,
                _ => continue,
            };

            for entry in dir_listing {
                let entry_path = match entry {
                    Ok(v) => v,
                    _ => continue,
                };

                if cur_files.contains(&entry_path.path()) {
                    continue;
                }

                let metadata = match entry_path.metadata() {
                    Ok(v) => v,
                    _ => continue,
                };

                if !metadata.is_file() {
                    continue;
                }

                new_files.push(entry_path.path());
            }
        }

        self.file_list.append(&mut new_files);
        *self.stats.initial_input_num = self.file_list.len();

        // Gerenate a hash for all the current files
        let mut cur_hash: [u8; 20] = [0; 20];
        for i in 0..self.file_list.len() {
            self.set_cur_file(i);
            self.load_cur_file(core)?;

            self.hasher.reset();
            self.hasher.input(&self.cur_file);
            self.hasher.result(&mut cur_hash);

            self.unique_files.insert(cur_hash);
        }

        Ok(())
    }

    pub fn save_new_inputs(&mut self, core: &mut CoreInterface) -> Result<(), PluginStatus> {
        let mut cur_hash: [u8; 20] = [0; 20];

        for cur_input_provider in &self.input_providers {
            // number of files that should be kept
            if cur_input_provider.length == 0 {
                continue;
            }

            let file_list = cur_input_provider.as_slice::<CFVec>();
            for cur_file in file_list {
                if cur_file.length == 0 {
                    continue;
                }

                let chunk_list = cur_file.as_slice::<CFBuf>();
                // Hash the file contents
                self.hasher.reset();
                for chunk in chunk_list {
                    self.hasher
                        .input(unsafe { from_raw_parts(chunk.buf, chunk.len) });
                }
                self.hasher.result(&mut cur_hash);

                //core.log(LOGLEVEL_INFO, &format!("'{}'", self.hasher.result_str()));
                //core.log(LOGLEVEL_INFO, &format!("{:p}", cur_file.data));

                // Check fo duplicate
                if self.unique_files.contains(&cur_hash) {
                    continue;
                }

                // Save to state folder
                self.result_dir.set_file_name(self.hasher.result_str());
                let mut f = match File::create(&self.result_dir) {
                    Ok(f) => f,
                    Err(e) => {
                        core.log(
                            LOGLEVEL_ERROR,
                            &format!(
                                "Failed to create new file '{}' : {}",
                                self.result_dir.to_string_lossy(),
                                e
                            ),
                        );
                        return Err(STATUS_PLUGINERROR);
                    }
                };
                //Write chunks to disk
                for chunk in chunk_list {
                    if let Err(e) = f.write_all(unsafe { from_raw_parts(chunk.buf, chunk.len) }) {
                        core.log(LOGLEVEL_ERROR, &format!("Failed to write file : {}", e));
                        return Err(STATUS_PLUGINERROR);
                    }
                }
                *self.stats.generated_input_num += 1;
                self.file_list.push(self.result_dir.clone());
                self.unique_files.insert(cur_hash);
            }
        }
        Ok(())
    }
}
