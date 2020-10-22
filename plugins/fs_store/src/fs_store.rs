use cflib::*;
use std::collections::HashSet;
use std::mem::MaybeUninit;
use std::path::PathBuf;

use ::crypto::sha1::Sha1;
use ::log::Level;

mod helpers;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, fuzz);
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
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let mut state = Box::new(State {
        hasher: Sha1::new(),
        unique_files: HashSet::new(),
        tmp_uid: [0; 20],
        tmp_str: String::new(),
        tmp_buf: Vec::new(),
        queue_dir: PathBuf::new(),
        is_input_list_owner: false,
        is_new_inputs_owner: false,
        num_inputs: match core.add_stat(&format!("{}num_files", TAG_PREFIX_TOTAL), NewStat::Num(0))
        {
            Ok(StatVal::Num(v)) => v,
            _ => return Err(From::from("Failed to reserve stat".to_string())),
        },
        input_list: unsafe { MaybeUninit::zeroed().assume_init() },
        new_inputs: unsafe { MaybeUninit::zeroed().assume_init() },
        owned_input_list: Vec::new(),
        owned_new_inputs: Vec::new(),
    });

    // Save our files in <state>/queue
    state
        .queue_dir
        .push(raw_to_ref!(*store.get(STORE_STATE_DIR).unwrap(), String));
    state.queue_dir.push("queue");

    // Create filesystem store
    if !state.queue_dir.is_dir() && std::fs::create_dir(&state.queue_dir).is_err() {
        core.log(
            Level::Error,
            &format!(
                "Failed to create directory '{}'",
                state.queue_dir.to_string_lossy()
            ),
        );
        return Err(From::from("Failed to create directory".to_string()));
    }

    // Grab or create input_list
    loop {
        if let Some(v) = store.get(STORE_INPUT_LIST) {
            if !state.is_input_list_owner {
                core.log(
                    Level::Info,
                    &format!("Using existing '{}' in store !", STORE_INPUT_LIST),
                );
            }
            state.input_list = raw_to_mutref!(*v, Vec<CfInputInfo>);
            break;
        } else {
            store.insert(
                String::from(STORE_INPUT_LIST),
                mutref_to_raw!(state.owned_input_list),
            );
            state.is_input_list_owner = true;
        }
    }

    // Grab or create new_inputs
    loop {
        if let Some(v) = store.get(STORE_NEW_INPUTS) {
            if !state.is_new_inputs_owner {
                core.log(
                    Level::Info,
                    &format!("Using existing '{}' in store !", STORE_NEW_INPUTS),
                );
            }
            state.new_inputs = raw_to_mutref!(*v, Vec<CfNewInput>);
            break;
        } else {
            store.insert(
                String::from(STORE_NEW_INPUTS),
                mutref_to_raw!(state.owned_new_inputs),
            );
            state.is_new_inputs_owner = true;
        }
    }

    // Get the input direcory with starting testcases
    let input_dir = raw_to_ref!(*store.get(STORE_INPUT_DIR).unwrap(), String);

    // Build our input_list from the filesystem
    core.log(Level::Info, "Scanning for inputs...");
    state.init(core, input_dir.as_str());

    *state.num_inputs.val = state.input_list.len() as _;

    if state.input_list.is_empty() {
        core.log(
            Level::Error,
            &format!(
                "No inputs found in {} or {}",
                input_dir,
                state.queue_dir.to_string_lossy()
            ),
        );
        return Err(From::from("No inputs".to_string()));
    }

    core.log(
        Level::Info,
        &format!("Found {} input(s) !", state.input_list.len()),
    );

    Ok(Box::into_raw(state) as _)
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
fn fuzz(core: &mut dyn PluginInterface, _store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Only task is to save new files to the filesystem
    state.save_new_inputs(core, true);
    std::thread::sleep(std::time::Duration::from_secs(1));
    Ok(())
}

// Unload and free our resources
fn destroy(
    _core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_take!(plugin_ctx, State);

    // If we created the input_list
    if state.is_input_list_owner {
        let _ = store.remove(STORE_INPUT_LIST);
    }

    // If we created the new_inputs
    if state.is_new_inputs_owner {
        let _ = store.remove(STORE_NEW_INPUTS);
    }

    Ok(())
}
