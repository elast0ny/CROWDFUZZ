use std::collections::{BinaryHeap, HashMap};
use std::mem::MaybeUninit;

use ::afl_lib::*;
use ::cflib::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, update_state);
cflib::register!(unload, destroy);

struct State {
    globals: AflGlobals,
    queue: Vec<AflQueueEntry>,
    inputs: &'static Vec<CfInputInfo>,
    num_execs: &'static u64,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let mut s = Box::new(unsafe {
        State {
            globals: AflGlobals::default(),
            queue: Vec::new(),
            // Core store vals
            num_execs: store.as_ref(STORE_NUM_EXECS, Some(core))?,
            // Plugin store vals
            inputs: MaybeUninit::zeroed().assume_init(),
        }
    });

    store.insert_exclusive(STORE_AFL_GLOBALS, &s.globals, Some(core))?;
    store.insert_exclusive(STORE_AFL_QUEUE, &s.globals, Some(core))?;

    let plugin_conf: &HashMap<String, String>;
    unsafe { plugin_conf = store.as_ref(STORE_PLUGIN_CONF, Some(core))? }

    s.load_conf(plugin_conf)?;

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
        s.inputs = store.as_ref(STORE_INPUT_LIST, Some(core))?;
    }

    s.queue.resize_with(s.inputs.len(), Default::default);

    Ok(())
}

// Perform our task in the fuzzing loop
fn update_state(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    // New inputs have been added to our input list !
    if s.inputs.len() > s.queue.len() {
        let mut val = AflQueueEntry::default();
        val.handicap = *s.num_execs - 1;
        s.queue.resize(s.inputs.len(), val);
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

    store.remove(STORE_AFL_GLOBALS).unwrap();
    store.remove(STORE_AFL_QUEUE).unwrap();

    Ok(())
}

impl State {
    pub fn load_conf(&mut self, plugin_conf: &HashMap<String, String>) -> Result<()> {
        Ok(())
    }
}
