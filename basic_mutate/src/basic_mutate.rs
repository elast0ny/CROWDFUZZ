use ::cflib::*;

extern crate rand;
use rand::{thread_rng, Rng};
use std::ffi::c_void;
use std::slice::from_raw_parts_mut;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(init, init);
cflib::register!(validate, validate);
cflib::register!(work, mutate_testcase);
cflib::register!(destroy, destroy);

struct State {
    input_bytes: &'static CVec,
    input_chunks: Vec<CTuple>,
    chunk_list: CVec,
}

extern "C" fn init(core_ptr: *mut CoreInterface) -> PluginStatus {
    let core = cflib::ctx_unchecked!(core_ptr);

    let mut state = Box::new(State {
        input_bytes: unsafe { &*std::ptr::null() },
        input_chunks: Vec::with_capacity(16),
        chunk_list: CVec {
            length: 0,
            capacity: 0,
            data: std::ptr::null_mut(),
        },
    });

    core.store_push_back(KEY_CUR_INPUT_CHUNKS_STR, &mut state.chunk_list as *mut _);

    core.priv_data = Box::into_raw(state) as *mut _;
    STATUS_SUCCESS
}

extern "C" fn validate(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let (core, state) = cflib::ctx_unchecked!(core_ptr, priv_data, State);

    // A plugin must set INPUT_BYTES for us to mutate
    state.input_bytes = cflib::store_get_ref!(mandatory, CVec, core, KEY_INPUT_BYTES_STR, 0);

    STATUS_SUCCESS
}

extern "C" fn destroy(core_ptr: *mut CoreInterface, priv_data: *mut c_void) -> PluginStatus {
    let core = cflib::ctx_unchecked!(core_ptr);

    let _state: Box<State> = unsafe { Box::from_raw(priv_data as *mut _) };
    let _: *mut c_void = core.store_pop_front(KEY_CUR_INPUT_CHUNKS_STR);

    STATUS_SUCCESS
}

///Select random byte in input and assign random value to it
extern "C" fn mutate_testcase(
    core_ptr: *mut CoreInterface,
    priv_data: *mut c_void,
) -> PluginStatus {
    let (_core, state) = cflib::ctx_unchecked!(core_ptr, priv_data, State);

    let input_bytes: &mut [u8] =
        unsafe { from_raw_parts_mut(state.input_bytes.data as *mut _, state.input_bytes.length) };

    // Randomly mutate some bytes
    let num_of_bytes_mutated = thread_rng().gen_range(0, state.input_bytes.length as _);
    for _ in 0..num_of_bytes_mutated {
        let rand_byte = unsafe {
            &mut *(state
                .input_bytes
                .data
                .offset(thread_rng().gen_range(0, state.input_bytes.length as _))
                as *mut u8)
        };
        *rand_byte = thread_rng().gen::<u8>();
    }

    state.input_chunks.clear();
    // Only one chunk for now as we just modify existing data
    state.input_chunks.push(CTuple {
        first: input_bytes.len(),
        second: input_bytes.as_ptr() as _,
    });

    // Make the input chunks point to our newly mutated input
    state.chunk_list.update_from_vec(&state.input_chunks);

    STATUS_SUCCESS
}
