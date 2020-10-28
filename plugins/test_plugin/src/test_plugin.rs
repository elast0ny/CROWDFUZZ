use cflib::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, fuzz);
cflib::register!(unload, destroy);

struct State {
    num_iter: StatNum,
    fuzzer_name: &'static String,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    let state = Box::new(State {
        // Create number that lives in the stats memory
        num_iter: core.new_stat_num(&format!("{}num_iter", TAG_PREFIX_TOTAL), 0)?,
        // Get refence to store value owned by the core
        fuzzer_name: unsafe {store.as_ref(STORE_FUZZER_ID, Some(core))}?,
    });

    core.info(&format!("Hello {} !", state.fuzzer_name));

    Ok(Box::into_raw(state) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let _state = box_ref!(plugin_ctx, State);
    
    core.debug("Validating !");

    Ok(())
}

// Perform our task in the fuzzing loop
fn fuzz(_core: &mut dyn PluginInterface, _store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()> {
    let ctx = box_ref!(plugin_ctx, State);

    *ctx.num_iter.val += 1;

    std::thread::sleep(std::time::Duration::from_secs(1));

    Ok(())
}

// Unload and free our resources
fn destroy(
    core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let _ctx = box_take!(plugin_ctx, State);

    core.debug("Unloading !");

    Ok(())
}
