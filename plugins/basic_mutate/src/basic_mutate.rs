use std::mem::MaybeUninit;

use ::cflib::*;
use ::rand::rngs::SmallRng;
use ::rand::{Rng, SeedableRng};

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, mutate_input);
cflib::register!(unload, destroy);

struct State {
    /// fast/non-crypto grade random
    rng: SmallRng,
    no_mutate: &'static bool,
    /// Reference to the currently selected input
    cur_input: &'static mut CfInput,
    
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let s = Box::new(unsafe {
        State {
            rng: SmallRng::from_rng(&mut ::rand::thread_rng()).unwrap(),
            // core store values
            no_mutate: store.as_mutref(STORE_NO_MUTATE, Some(core))?,
            // Plugin store values
            cur_input: MaybeUninit::zeroed().assume_init(),
        }
    });

    Ok(Box::into_raw(s) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    // We need a plugin that creates in input_bytes
    unsafe {
        s.cur_input = store.as_mutref(STORE_INPUT_BYTES, Some(core))?;
    }

    Ok(())
}

// Perform our task in the fuzzing loop
fn mutate_input(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    if *s.no_mutate || s.cur_input.is_empty() {
        // Input is empty ??
        return Ok(());
    }

    let input_len = s.cur_input.len();
    // Randomly mutate some bytes in the first chunk
    let num_of_bytes_mutated = s.rng.gen_range(0, input_len);
    for _ in 0..num_of_bytes_mutated {
        s.cur_input[s.rng.gen_range(0, input_len)] = s.rng.gen::<u8>();
    }

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
