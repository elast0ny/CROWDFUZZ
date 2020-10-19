use cflib::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, fuzz);
cflib::register!(unload, destroy);

// Initialize our plugin
fn init(ctx: &dyn PluginInterface) -> PluginStatus {    
    ctx.log(::log::Level::Info, "initializing");
    PluginStatus::Success
}

// Make sure we have everything to fuzz properly
fn validate(ctx: &dyn PluginInterface) -> PluginStatus {
    ctx.log(::log::Level::Info, "validating");
    PluginStatus::Success
}

// Perform our task in the fuzzing loop
fn fuzz(ctx: &dyn PluginInterface) -> PluginStatus {
    ctx.log(::log::Level::Info, "fuzzing");
    PluginStatus::Success
}

// Unload and free our resources
fn destroy(ctx: &dyn PluginInterface) -> PluginStatus {
    ctx.log(::log::Level::Info, "destroying");
    PluginStatus::Success
}