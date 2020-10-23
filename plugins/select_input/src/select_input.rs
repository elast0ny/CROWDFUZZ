use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::fs::File;
use std::io::prelude::*;

use ::cflib::*;
use ::rand::{Rng, SeedableRng};
use ::rand::rngs::SmallRng;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, select_input);
cflib::register!(unload, destroy);

struct State {
    /// Use a fast/non-crypto grade random
    rng: SmallRng,
    cur_input_idx: usize,
    tmp_buf: Vec<u8>,
    cur_input: CfInput,
    input_list: &'static mut Vec<CfInputInfo>,
    priority_list: VecDeque<usize>,
    num_priority_inputs: StatNum,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let mut state = Box::new(unsafe {
        State {
            rng: SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap(),
            cur_input_idx: 0,
            tmp_buf: Vec::new(),
            cur_input: CfInput::default(),
            priority_list: VecDeque::new(),
            input_list: MaybeUninit::zeroed().assume_init(),
            num_priority_inputs: match core.add_stat(&format!("{}num_priority_inputs", TAG_PREFIX_TOTAL), NewStat::Num(0))
            {
                Ok(StatVal::Num(v)) => v,
                _ => return Err(From::from("Failed to reserve stat".to_string())),
            },
        }
    });

    // We should be the only plugin with these values
    if store.get(STORE_INPUT_IDX).is_some()
        || store.get(STORE_INPUT_BYTES).is_some()
        || store.get("select_priority_list").is_some()
    {
        core.log(LogLevel::Error, "Another plugin is already selecting inputs !");
        return Err(From::from("Duplicate select plugins".to_string()));
    }

    // Add our values to the store
    store.insert(
        STORE_INPUT_IDX.to_string(),
        ref_to_raw!(state.cur_input_idx),
    );
    store.insert(
        STORE_INPUT_BYTES.to_string(),
        mutref_to_raw!(state.cur_input),
    );
    store.insert(
        "select_priority_list".to_string(),
        mutref_to_raw!(state.priority_list),
    );

    Ok(Box::into_raw(state) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    match store.get(STORE_INPUT_LIST) {
        Some(v) => state.input_list = raw_to_mutref!(*v, Vec<CfInputInfo>),
        None => {
            core.log(LogLevel::Error, "No plugin managing input_list !");
            return Err(From::from("No inputs".to_string()));
        }
    };

    Ok(())
}

// Perform our task in the fuzzing loop
fn select_input(
    core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    *state.num_priority_inputs.val = state.priority_list.len() as _;
    state.cur_input_idx = match state.priority_list.pop_front() {
        Some(idx) => idx,
        None => {
            // No priority, just randomly pick a file
            state.rng.gen_range(0, state.input_list.len())
        }
    };

    let input_info = unsafe{state.input_list.get_unchecked(state.cur_input_idx)};

    state.tmp_buf.clear();
    // No need to read off disk, content was inlined in the input info
    if let Some(contents) = &input_info.contents {
        // Copy original contents into input_bytes
        for chunk in &contents.chunks {
            state.tmp_buf.extend_from_slice(chunk);
        }
    } else {
        // Lets read contents from disk
        let p = match &input_info.path {
            Some(p) => p.as_path(),
            None => {
                core.log(LogLevel::Error, &format!("input[{}] has no content or path info !", state.cur_input_idx));
                return Err(From::from("No input contents".to_string()));
            }
        };
        // Open file
        let mut fin = match File::open(p) {
            Ok(f) => f,
            _ => return Err(From::from("No input contents".to_string())),
        };
        // Read contents
        if fin.read_to_end(&mut state.tmp_buf).is_err() {
            return Err(From::from("No input contents".to_string()));
        }
    }

    state.cur_input.chunks.clear();
    state.cur_input.chunks.push(state.tmp_buf.as_mut_slice());

    Ok(())
}

// Unload and free our resources
fn destroy(_core: &mut dyn PluginInterface, store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()> {
    let _ctx = box_take!(plugin_ctx, State);

    let _ = store.remove(STORE_INPUT_IDX);
    let _ = store.remove(STORE_INPUT_BYTES);
    let _ = store.remove("select_priority_list");

    Ok(())
}
