use std::mem::MaybeUninit;

use ::afl_lib::*;
use ::cflib::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, update_state);
cflib::register!(unload, destroy);

struct State {
    globals: AflState,
    queue: Vec<AflQueueEntry>,
    cur_input_idx: &'static usize,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let mut state = Box::new(unsafe {
        State {
            globals: AflState::default(),
            queue: Vec::new(),
            cur_input_idx: MaybeUninit::zeroed().assume_init(),
        }
    });

    // Insert the AflState vec to the store
    store_insert_exclusive!(core, store, STORE_AFL_STATE, mutref_to_raw!(state.globals));
    // Insert the AflInputInfo vec to the store
    store_insert_exclusive!(core, store, STORE_AFL_QUEUE, mutref_to_raw!(state.queue));

    Ok(Box::into_raw(state) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Take ref to cur_input_idx
    state.cur_input_idx = raw_to_ref!(*store_get_mandatory!(core, store, STORE_INPUT_IDX), usize);

    Ok(())
}

// Perform our task in the fuzzing loop
fn update_state(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Increase our queue vec if indexing above it
    if *state.cur_input_idx >= state.queue.len() {
        state
            .queue
            .resize_with(*state.cur_input_idx + 1, Default::default);
    }

    Ok(())
}

// Unload and free our resources
fn destroy(
    _core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let _state = box_take!(plugin_ctx, State);

    let _ = store.remove(STORE_AFL_STATE).unwrap();
    let _ = store.remove(STORE_AFL_QUEUE).unwrap();

    Ok(())
}
