use cflib::*;
use std::collections::{HashSet, hash_map::Entry};
use std::mem::MaybeUninit;
use std::path::PathBuf;

use ::log::Level;
use ::crypto::sha1::Sha1;

mod helpers;
use helpers::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, fuzz);
cflib::register!(unload, destroy);

pub struct State<'i> {
    hasher: Sha1,
    unique_files: HashSet<[u8; 20]>,
    tmp_uid: [u8; 20],
    tmp_str: String,
    queue_dir: PathBuf,

    is_input_list_owner: bool,
    input_list: &'i mut Vec<CfInputInfo>,
    owned_new_list: Vec<CfInputInfo>,
    
    is_new_inputs_owner: bool,
    new_inputs: &'i mut Vec<&'i mut CfInput>,
    owned_new_inputs: Vec<CfInputInfo>,
}

// Initialize our plugin
fn init(core: &dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {    
    
    #[allow(invalid_value)]
    let mut state = State {
        hasher: Sha1::new(),
        unique_files: HashSet::new(),
        tmp_uid: [0; 20],
        tmp_str: String::with_capacity(40),
        queue_dir: PathBuf::new(),
        is_input_list_owner: false,
        is_new_inputs_owner: false,
        input_list: unsafe{MaybeUninit::zeroed().assume_init()},
        new_inputs: unsafe{MaybeUninit::zeroed().assume_init()},
        owned_new_list: Vec::new(),
        owned_new_inputs: Vec::new(),
    };
        
    core.log(::log::Level::Info, "Getting store values...");

    // Save our files in <state>/queue
    state.queue_dir.push(box_ref!(*store.get(STORE_STATE_DIR).unwrap(), &str));
    state.queue_dir.push("queue");

    // Input list
    match store.entry(String::from(STORE_INPUT_LIST)) {
        Entry::Occupied(e) => {
            core.log(Level::Info, &format!("Using existing '{}' in store !", e.key()));
            state.input_list = *box_ref!(*e.get(), &mut Vec<CfInputInfo>);
        },
        Entry::Vacant(e) => {
            e.insert(box_leak!(&mut state.owned_new_list));
            state.is_input_list_owner = true;
        }
    }

    Ok(box_leak!(state))
}

// Make sure we have everything to fuzz properly
fn validate(core: &dyn PluginInterface, store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // new_inputs
    match store.entry(String::from(STORE_NEW_INPUTS)) {
        Entry::Occupied(e) => {
            core.log(Level::Info, &format!("Using existing '{}' in store !", e.key()));
            state.new_inputs = *box_ref!(*e.get(), &mut Vec<&mut CfInput>);
        },
        Entry::Vacant(e) => {
            e.insert(box_leak!(&mut state.owned_new_inputs));
            state.is_new_inputs_owner = true;
        }
    }

    Ok(())
}

// Perform our task in the fuzzing loop
fn fuzz(_core: &dyn PluginInterface, _store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    let new_inputs: Vec<_> = state.new_inputs.drain(..).collect();
    for new_input in new_inputs {
        state.save_input(new_input);
    }

    std::thread::sleep(std::time::Duration::from_secs(1));
    
    Ok(())
}

// Unload and free our resources
fn destroy(_core: &dyn PluginInterface, store: &mut CfStore, plugin_ctx: *mut u8) -> Result<()> {
    let state = box_take!(plugin_ctx, State);

    if state.is_input_list_owner {
        if let Some(e) = store.remove(STORE_INPUT_LIST) {
            drop(box_take!(e, &mut Vec<u8>));
        }
    }

    if state.is_new_inputs_owner {
        if let Some(e) = store.remove(STORE_NEW_INPUTS) {
            drop(box_take!(e, &mut Vec<u8>));
        }
    }

    Ok(())
}