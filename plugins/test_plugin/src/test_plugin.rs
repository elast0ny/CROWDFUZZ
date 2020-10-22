use cflib::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, fuzz);
cflib::register!(unload, destroy);

struct State {
    num_iter: usize,
    fuzzer_name: &'static String,
}

// Initialize our plugin
fn init(core: &dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {    
    let state = Box::new(State {
        num_iter: 0,
        fuzzer_name: raw_to_ref!(*store.get(STORE_FUZZER_ID).unwrap(), String),
    });

    let val = store.get(STORE_FUZZER_ID).unwrap();

    core.log(::log::Level::Info, &format!("initializing for {:p} {:p}", val, *val));
    core.log(::log::Level::Info, &format!("initializing for {} !", state.fuzzer_name));
    
    Ok(Box::into_raw(state) as _)
}

// Make sure we have everything to fuzz properly
fn validate(core: &dyn PluginInterface, _store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()> {
    let _state = box_ref!(plugin_ctx, State);
    
    core.log(::log::Level::Info, "validating");

    Ok(())
}

// Perform our task in the fuzzing loop
fn fuzz(_core: &dyn PluginInterface, _store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()> {
    let ctx = box_ref!(plugin_ctx, State);

    ctx.num_iter += 1;

    std::thread::sleep(std::time::Duration::from_secs(1));
    
    Ok(())
}

// Unload and free our resources
fn destroy(core: &dyn PluginInterface, _store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()> {
    let _ctx = box_take!(plugin_ctx, State);

    core.log(::log::Level::Info, "destroying");

    Ok(())
}