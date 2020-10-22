use std::mem::MaybeUninit;

use ::cflib::*;
use ::log::Level::*;
use ::rand::{Rng, SeedableRng};
use ::rand::rngs::SmallRng;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, mutate_input);
cflib::register!(unload, destroy);

struct State {
    /// fast/non-crypto grade random
    rng: SmallRng,
    /// Reference to the currently selected input
    cur_input: &'static mut CfInput,
}

// Initialize our plugin
fn init(_core: &mut dyn PluginInterface, _store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let state = Box::new(unsafe {
        State {
            rng: SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap(),
            cur_input: MaybeUninit::zeroed().assume_init(),
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
    core.log(::log::Level::Info, "validating");

    // We need a plugin that creates in input_bytes
    if let Some(v) = store.get(STORE_INPUT_BYTES) {
        state.cur_input = raw_to_mutref!(*v, CfInput);
    } else {
        core.log(Error, "No plugin create input_bytes !");
        return Err(From::from("No selected input".to_string()));
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

    if state.cur_input.chunks.is_empty() {
        // Input is empty ??
        return Ok(());
    }

    let first_chunk = unsafe{state.cur_input.chunks.get_unchecked_mut(0)};

    // Randomly mutate some bytes in the first chunk
    let num_of_bytes_mutated = state.rng.gen_range(0, first_chunk.len());
    for _ in 0..num_of_bytes_mutated {
        first_chunk[state.rng.gen_range(0, first_chunk.len())] = state.rng.gen::<u8>();
    }

    Ok(())
}

// Unload and free our resources
fn destroy(_core: &mut dyn PluginInterface, _store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()> {
    let _state = box_take!(plugin_ctx, State);
    Ok(())
}
