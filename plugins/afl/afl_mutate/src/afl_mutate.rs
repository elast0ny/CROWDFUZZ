use std::mem::MaybeUninit;

pub use ::afl_lib::*;
pub use ::cflib::*;

mod mutators;
pub use mutators::*;
mod bit_flip;
pub use bit_flip::*;
mod arithmetic;
pub use arithmetic::*;
mod interesting;
pub use interesting::*;
mod havoc;
pub use havoc::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, mutate_input);
cflib::register!(unload, destroy);

struct State {
    /// Reference to the currently selected input
    cur_input: &'static mut CfInput,
    cur_input_idx: &'static usize,
    reuse_input: &'static mut bool,
    globals: &'static mut AflState,
    stage: Vec<MutateStage>,
}

// Initialize our plugin
fn init(_core: &mut dyn PluginInterface, _store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let state = Box::new(unsafe {
        State {
            cur_input: MaybeUninit::zeroed().assume_init(),
            cur_input_idx: MaybeUninit::zeroed().assume_init(),
            reuse_input: MaybeUninit::zeroed().assume_init(),
            globals: MaybeUninit::zeroed().assume_init(),
            stage: Vec::new(),
        }
    });

    Ok(Box::into_raw(state) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Grab all the keys we need to function
    state.cur_input = raw_to_mutref!(
        *store_get_mandatory!(core, store, STORE_INPUT_BYTES),
        CfInput
    );
    state.cur_input_idx = raw_to_ref!(*store_get_mandatory!(core, store, STORE_INPUT_IDX), usize);
    state.reuse_input = raw_to_mutref!(*store_get_mandatory!(core, store, STORE_RESTORE_INPUT), bool);
    state.globals = raw_to_mutref!(
        *store_get_mandatory!(core, store, STORE_AFL_STATE),
        AflState
    );

    Ok(())
}

// Perform our task in the fuzzing loop
fn mutate_input(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Add new stage entries for new inputs
    if *state.cur_input_idx >= state.stage.len() {
        state.stage.resize_with(state.cur_input_idx + 1, MutateStage::default)
    }

    // Get which stage we're at for this input
    let stage = unsafe {state.stage.get_unchecked_mut(*state.cur_input_idx)};

    // Progress through the mutation stage
    *state.reuse_input = stage.mutate(state.globals.skip_deterministic, state.cur_input);

    Ok(())
}

// Unload and free our resources
fn destroy(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let _state = box_take!(plugin_ctx, State);
    Ok(())
}
