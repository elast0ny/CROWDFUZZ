use std::collections::{HashMap, HashSet};
use std::mem::MaybeUninit;
use std::path::PathBuf;

use ::cflib::*;
use ::crypto::sha1::Sha1;

mod helpers;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, save_new);
cflib::register!(unload, destroy);

pub struct State {
    hasher: Sha1,
    unique_files: HashSet<[u8; 20]>,
    tmp_uid: [u8; 20],
    tmp_str: String,
    tmp_buf: Vec<u8>,
    queue_dir: PathBuf,
    num_inputs: StatNum,

    is_input_list_owner: bool,
    input_list: &'static mut Vec<CfInputInfo>,
    owned_input_list: Vec<CfInputInfo>,
    is_new_inputs_owner: bool,
    new_inputs: &'static mut Vec<CfNewInput>,
    owned_new_inputs: Vec<CfNewInput>,
    stat_queue_dir: StatStr,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let mut s = Box::new(unsafe {
        State {
            hasher: Sha1::new(),
            unique_files: HashSet::new(),
            tmp_uid: [0; 20],
            tmp_str: String::new(),
            tmp_buf: Vec::new(),
            queue_dir: PathBuf::new(),
            is_input_list_owner: false,
            is_new_inputs_owner: false,
            num_inputs: MaybeUninit::zeroed().assume_init(),
            owned_input_list: Vec::new(),
            owned_new_inputs: Vec::new(),
            input_list: MaybeUninit::zeroed().assume_init(),
            new_inputs: MaybeUninit::zeroed().assume_init(),
            stat_queue_dir: MaybeUninit::zeroed().assume_init(),
        }
    });

    // Grab needed values from plugin store
    let input_dir: &String;
    let state_dir: &String;
    let plugin_conf: &HashMap<String, String>;
    unsafe {
        state_dir = store.as_ref(STORE_STATE_DIR, Some(core))?;
        input_dir = store.as_ref(STORE_INPUT_DIR, Some(core))?;
        plugin_conf = store.as_ref(STORE_PLUGIN_CONF, Some(core))?;

        let (val, is_owned) =
            store.as_mutref_or_insert(STORE_INPUT_LIST, &mut s.owned_input_list, Some(core))?;
        s.input_list = val;
        s.is_input_list_owner = is_owned;

        let (val, is_owned) =
            store.as_mutref_or_insert(STORE_NEW_INPUTS, &mut s.owned_new_inputs, Some(core))?;
        s.new_inputs = val;
        s.is_new_inputs_owner = is_owned;
    }

    // Create queue dir
    // Save our files in <s>/X
    s.queue_dir.push(state_dir);
    if let Some(p) = plugin_conf.get("queue_dir") {
        s.queue_dir.push(p);
    } else {
        s.queue_dir.push("queue");
    }

    let tmp: &str = s.queue_dir.to_str().unwrap();
    s.stat_queue_dir =
        core.new_stat_str(&format!("queue_dir{}", TAG_POSTFIX_PATH), tmp.len(), tmp)?;
    s.num_inputs = core.new_stat_num(&format!("{}total_files", TAG_PREFIX_TOTAL), 0)?;

    // Create filesystem store
    if !s.queue_dir.is_dir() && std::fs::create_dir(&s.queue_dir).is_err() {
        core.error(&format!(
            "Failed to create directory '{}'",
            s.queue_dir.to_string_lossy()
        ));
        return Err(From::from("Failed to create directory".to_string()));
    }

    // Build our input_list from the filesystem
    core.info("Scanning for inputs...");
    s.init(core, input_dir.as_str());

    if s.input_list.is_empty() {
        core.error(&format!(
            "No inputs found in {} or {}",
            input_dir,
            s.queue_dir.to_string_lossy()
        ));
        return Err(From::from("No inputs".to_string()));
    }

    core.info(&format!("Found {} input(s) !", s.input_list.len()));

    Ok(Box::into_raw(s) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    _core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    _plugin_ctx: *mut u8,
) -> Result<()> {
    // We dont rely on any other plugin
    Ok(())
}

// Perform our task in the fuzzing loop
fn save_new(
    core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    // Only task is to save new files to the filesystem
    s.save_new_inputs(core, true);

    Ok(())
}

// Unload and free our resources
fn destroy(
    _core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_take!(plugin_ctx, State);

    // If we created the input_list
    if s.is_input_list_owner {
        let _ = store.remove(STORE_INPUT_LIST);
    }

    // If we created the new_inputs
    if s.is_new_inputs_owner {
        let _ = store.remove(STORE_NEW_INPUTS);
    }

    Ok(())
}
