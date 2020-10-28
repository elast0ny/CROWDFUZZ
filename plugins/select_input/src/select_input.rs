use std::collections::VecDeque;
use std::fs::File;
use std::io::prelude::*;
use std::mem::MaybeUninit;

use ::cflib::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, select_input);
cflib::register!(unload, destroy);

struct State {
    cur_input: CfInput,
    restore_input: bool,
    cur_input_idx: usize,
    seq_input_idx: usize,
    orig_buf: Vec<u8>,
    fuzz_buf: Vec<u8>,
    input_list: &'static Vec<CfInputInfo>,
    no_select: &'static bool,
    priority_list: VecDeque<usize>,
    num_priority_inputs: StatNum,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let state = Box::new(unsafe {
        State {
            cur_input_idx: 0,
            seq_input_idx: 0,
            orig_buf: Vec::new(),
            fuzz_buf: Vec::new(),
            cur_input: CfInput::default(),
            priority_list: VecDeque::new(),
            restore_input: false,
            // Stats
            num_priority_inputs: core
                .new_stat_num(&format!("{}num_priority_inputs", TAG_PREFIX_TOTAL), 0)?,
            // Core store values
            no_select: store.as_ref(STORE_NO_SELECT, Some(core))?,
            // Plugin store values
            input_list: MaybeUninit::zeroed().assume_init(),
        }
    });

    // Add our values to the store
    store.insert_exclusive(STORE_INPUT_IDX, &state.cur_input_idx, Some(core))?;
    store.insert_exclusive(STORE_INPUT_BYTES, &state.cur_input, Some(core))?;
    store.insert_exclusive(STORE_RESTORE_INPUT, &state.restore_input, Some(core))?;
    store.insert_exclusive("select_priority_list", &state.priority_list, Some(core))?;

    Ok(Box::into_raw(state) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Make sure someone created INPUT_LIST
    state.input_list = unsafe { store.as_ref(STORE_INPUT_LIST, Some(core))? };

    Ok(())
}

// Perform our task in the fuzzing loop
fn select_input(
    core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Update number of indexes in priority list
    *state.num_priority_inputs.val = state.priority_list.len() as _;

    // Input selection currently disabled
    if *state.no_select {
        return Ok(());
    }

    // We will select a new input
    if !state.restore_input {
        // Pick the next input index
        match state.priority_list.pop_front() {
            Some(idx) => state.cur_input_idx = idx,
            None => {
                // Just get the next input
                state.cur_input_idx = state.seq_input_idx;
                state.seq_input_idx += 1;
                if state.seq_input_idx == state.input_list.len() {
                    state.seq_input_idx = 0;
                }
            }
        };

        // Get current input info
        let input_info = unsafe { state.input_list.get_unchecked(state.cur_input_idx) };

        state.orig_buf.clear();
        // If content is inlined in the input info
        if let Some(contents) = &input_info.contents {
            for chunk in &contents.chunks {
                state.orig_buf.extend_from_slice(chunk);
            }
        } else {
            // Lets read contents from disk
            let p = match &input_info.path {
                Some(p) => p.as_path(),
                None => {
                    core.error(&format!(
                        "input[{}] has no content or path info !",
                        state.cur_input_idx
                    ));
                    return Err(From::from("No input contents".to_string()));
                }
            };
            // Open file
            let mut fin = match File::open(p) {
                Ok(f) => f,
                _ => return Err(From::from("No input contents".to_string())),
            };
            // Read contents
            if fin.read_to_end(&mut state.orig_buf).is_err() {
                return Err(From::from("No input contents".to_string()));
            }
        }
    }

    // Copy orig into fuzz_buf
    state.fuzz_buf.clear();
    state.fuzz_buf.extend_from_slice(&state.orig_buf);

    // Make fuzz_buf new input
    state.cur_input.chunks.clear();
    state.cur_input.chunks.push(state.fuzz_buf.as_mut_slice());

    Ok(())
}

// Unload and free our resources
fn destroy(
    _core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let _ctx = box_take!(plugin_ctx, State);

    // Remove our store entries
    let _ = store.remove(STORE_INPUT_IDX);
    let _ = store.remove(STORE_INPUT_BYTES);
    let _ = store.remove(STORE_RESTORE_INPUT);
    let _ = store.remove("select_priority_list");

    Ok(())
}
