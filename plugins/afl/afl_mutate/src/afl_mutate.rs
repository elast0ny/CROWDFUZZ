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
    inputs: &'static Vec<CfInputInfo>,
    input_stages: Vec<InputMutateStage>,
}

// Initialize our plugin
fn init(_core: &mut dyn PluginInterface, _store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let state = Box::new(unsafe {
        State {
            input_stages: Vec::new(),

            /// Plugin store values
            cur_input: MaybeUninit::zeroed().assume_init(),
            cur_input_idx: MaybeUninit::zeroed().assume_init(),
            globals: MaybeUninit::zeroed().assume_init(),
            reuse_input: MaybeUninit::zeroed().assume_init(),
            inputs: MaybeUninit::zeroed().assume_init(),
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
    unsafe {
        state.cur_input = store.as_mutref(STORE_INPUT_BYTES, Some(core))?;
        state.cur_input_idx = store.as_ref(STORE_INPUT_IDX, Some(core))?;
        state.globals = store.as_mutref(STORE_AFL_STATE, Some(core))?;
        state.reuse_input = store.as_mutref(STORE_RESTORE_INPUT, Some(core))?;
        state.inputs = store.as_mutref(STORE_INPUT_LIST, Some(core))?;
    }
    Ok(())
}

// Perform our task in the fuzzing loop
fn mutate_input(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Detect new inputs and init their mutate stage
    if *state.cur_input_idx >= state.input_stages.len() {
        let num_new_inputs = (state.cur_input_idx + 1) - state.input_stages.len();
        let input_info = unsafe { state.inputs.get_unchecked(*state.cur_input_idx) };
        state.input_stages.reserve(num_new_inputs);
        for _i in 0..num_new_inputs {
            state.input_stages.push(InputMutateStage::new(
                state.globals.skip_deterministic,
                input_info.len,
            ));
        }
    }

    // Get which stage we're at for this input
    let stage = unsafe { state.input_stages.get_unchecked_mut(*state.cur_input_idx) };

    // Progress through the mutation stage
    *state.reuse_input = stage.mutate(state.cur_input);

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
