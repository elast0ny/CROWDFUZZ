use std::slice::from_raw_parts;
use std::ffi::{c_void};
use std::collections::HashSet;
use std::path::PathBuf;
use std::fs::File;
use std::io::prelude::*;

use ::crypto::digest::Digest;
use ::crypto::sha1::Sha1;

use ::cflib::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(init, init);
cflib::register!(validate, validate);
cflib::register!(work, post_run);
cflib::register!(destroy, destroy);

struct State {
    cur_hash: [u8; 20],
    hasher: Sha1,
    result_dir: PathBuf,
    unique_files: HashSet<[u8; 20]>,
    pub_input_chunks: &'static CVec,
    new_inputs: Vec<CVec>,
    pub_new_inputs: CVec,
    exit_status: &'static CTuple,
}

extern "C" fn init(core_ptr: *mut CoreInterface) -> PluginStatus {
    let core = cflib::ctx_unchecked!(core_ptr);

    let mut state = unsafe {Box::new(State {
        cur_hash: [0; 20],
        hasher: Sha1::new(),
        result_dir: PathBuf::new(),
        unique_files: HashSet::new(),
        pub_input_chunks: &*std::ptr::null(),
        new_inputs: Vec::with_capacity(1),
        pub_new_inputs: CVec {
            length: 0,
            capacity: 0,
            data: std::ptr::null_mut(),
        },
        exit_status: &*std::ptr::null(),
    })};
    
    core.store_push_front(KEY_NEW_INPUT_LIST_STR, &mut state.pub_new_inputs as *mut _);

    core.priv_data = Box::into_raw(state) as *mut _;

    STATUS_SUCCESS
}

extern "C" fn validate(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let (core, state) = cflib::ctx_unchecked!(core_ptr, priv_data, State);

    // exit_status of the last run
    state.exit_status = cflib::store_get_ref!(mandatory, CTuple, core, KEY_EXIT_STATUS_STR, 0);
    // Input contents of the last run
    state.pub_input_chunks = cflib::store_get_ref!(mandatory, CVec, core, KEY_CUR_INPUT_CHUNKS_STR, 0);

    state.result_dir = PathBuf::from(cflib::store_get_ref!(mandatory, str, core, KEY_RESULT_DIR_STR, 0));
    
    state.result_dir.push("crashes/");
    if let Err(e) = std::fs::create_dir_all(&state.result_dir) {
        core.log(LOGLEVEL_ERROR, &format!("Failed to create directory '{}' : {}", state.result_dir.to_string_lossy(), e));    
        return STATUS_PLUGINERROR;
    }
    core.log(LOGLEVEL_INFO, &format!("Writing crashes to '{}'", state.result_dir.to_string_lossy()));
    state.result_dir.push("dummyfilename");

    state.new_inputs.push(CVec {
        length: 0,
        capacity: 0,
        data: 0 as _,
    });
    
    STATUS_SUCCESS
}

extern "C" fn destroy(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let core = cflib::ctx_unchecked!(core_ptr);

    let _state: Box<State> = unsafe { Box::from_raw(priv_data as *mut _) };
    let _: *mut c_void = core.store_pop_front(KEY_NEW_INPUT_LIST_STR);

    STATUS_SUCCESS
}

///Select random byte in input and assign random value to it
extern "C" fn post_run(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let (core, state) = cflib::ctx_unchecked!(core_ptr, priv_data, State);

    state.hasher.reset();

    // Make a hash of the input bytes
    let chunks: &[CTuple] = state.pub_input_chunks.as_slice();
    for chunk in chunks {
        state.hasher.input(unsafe{from_raw_parts(chunk.second as _, chunk.first)});
    }
    state.hasher.result(&mut state.cur_hash);

    state.pub_new_inputs.length = 0;

    // Already seen this file
    if state.unique_files.contains(&state.cur_hash) {
        return STATUS_SUCCESS;
    }

    // Always keep the input, afl would only keep new coverage generating inputs here
    state.new_inputs[0].length = state.pub_input_chunks.length;
    state.new_inputs[0].capacity = state.pub_input_chunks.capacity;
    state.new_inputs[0].data = state.pub_input_chunks.data;
    state.pub_new_inputs.update_from_vec(&state.new_inputs);

    // Dont save anything for now
    state.pub_new_inputs.length = 0;

    //core.log(LOGLEVEL_INFO, &format!("'{}'", state.hasher.result_str()));
    //core.log(LOGLEVEL_INFO, &format!("{:p}", state.pub_input_chunks.data));
    
    // Got a crash, save it
    if state.exit_status.first != 0 {
        state.result_dir.set_file_name(state.hasher.result_str());
        let mut f = match File::create(&state.result_dir) {
            Ok(f) => f,
            Err(e) => {
                core.log(LOGLEVEL_ERROR, &format!("Failed to create new file '{}' : {}", state.result_dir.to_string_lossy(), e));
                return STATUS_PLUGINERROR;
            }
        };
        //Write chunks to disk
        for chunk in chunks {
            if let Err(e) = f.write_all(unsafe{from_raw_parts(chunk.second as _, chunk.first)}) {
                core.log(LOGLEVEL_ERROR, &format!("Failed to write : {}", e));
                return STATUS_PLUGINERROR;
            }
        }
    }/* else {
        core.log(LOGLEVEL_DEBUG, &format!("Exit status : {}", state.exit_status.second));
    }*/

    STATUS_SUCCESS
}

