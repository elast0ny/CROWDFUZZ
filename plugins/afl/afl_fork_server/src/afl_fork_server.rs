use std::mem::MaybeUninit;

use ::afl_lib::*;
use ::cflib::*;

::cfg_if::cfg_if! {
    if #[cfg(target_os = "windows")] {
        mod windows;
        use windows as os;
    } else {
        mod linux;
        use linux as os;
    }
}

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, run_target);
cflib::register!(unload, destroy);

struct State {
    afl: &'static mut AflGlobals,
}

// Initialize our plugin
fn init(_core: &mut dyn PluginInterface, _store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let s = Box::new(unsafe {
        State {
            // Plugin store vals
            afl: MaybeUninit::zeroed().assume_init(),
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

    unsafe {
        s.afl = store.as_mutref(STORE_AFL_GLOBALS, Some(core))?;
    }

    Ok(())
}

// Perform our task in the fuzzing loop
fn run_target(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    _plugin_ctx: *mut u8,
) -> Result<()> {
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