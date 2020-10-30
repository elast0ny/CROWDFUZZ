use std::collections::BinaryHeap;

use std::fs::File;
use std::io::prelude::*;
use std::mem::MaybeUninit;

use ::cflib::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, select_input);
cflib::register!(unload, destroy);

struct State {
    cur_input: CfInput,
    restore_input: bool,
    cur_input_idx: usize,
    seq_input_idx: usize,
    orig_buf: Vec<u8>,
    fuzz_buf: Vec<u8>,
    input_list: &'static Vec<CfInputInfo>,
    no_select: &'static bool,
    priority_list: BinaryHeap<InputPriority>,
    num_priority_inputs: StatNum,
    num_old_inputs: usize,
    num_new_inputs: StatNum,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let s = Box::new(unsafe {
        State {
            cur_input_idx: 0,
            seq_input_idx: 0,
            orig_buf: Vec::new(),
            fuzz_buf: Vec::new(),
            cur_input: CfInput::default(),
            priority_list: BinaryHeap::new(),
            restore_input: false,
            num_old_inputs: 0,
            // Stats
            num_priority_inputs: core
                .new_stat_num(&format!("{}priority_inputs", TAG_PREFIX_TOTAL), 0)?,
            num_new_inputs: core
            .new_stat_num(&format!("{}new_inputs", TAG_PREFIX_TOTAL), 0)?,
            // Core store values
            no_select: store.as_ref(STORE_NO_SELECT, Some(core))?,
            // Plugin store values
            input_list: MaybeUninit::zeroed().assume_init(),
        }
    });

    // Add our values to the store
    store.insert_exclusive(STORE_INPUT_IDX, &s.cur_input_idx, Some(core))?;
    store.insert_exclusive(STORE_INPUT_BYTES, &s.cur_input, Some(core))?;
    store.insert_exclusive(STORE_RESTORE_INPUT, &s.restore_input, Some(core))?;
    store.insert_exclusive(STORE_INPUT_PRIORITY, &s.priority_list, Some(core))?;

    Ok(Box::into_raw(s) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    // Make sure someone created INPUT_LIST
    s.input_list = unsafe { store.as_ref(STORE_INPUT_LIST, Some(core))? };

    if !s.input_list.is_empty() {
        s.seq_input_idx = s.input_list.len() - 1;
    }

    s.num_old_inputs = s.input_list.len();

    Ok(())
}

// Perform our task in the fuzzing loop
fn select_input(
    core: &mut dyn PluginInterface,
    _store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    // Update number of indexes in priority list
    *s.num_priority_inputs.val = s.priority_list.len() as u64;
    *s.num_new_inputs.val = (s.num_old_inputs - s.input_list.len()) as u64;

    // Input selection currently disabled
    if *s.no_select {
        //core.trace("No select !");
        return Ok(());
    }

    // We will select a new input
    if !s.restore_input {
        match s.priority_list.pop() {
            Some(v) => {
                // This is the highest weighted input in the priority list
                s.cur_input_idx = v.idx;
            }
            None => {
                // Just get the next input
                s.seq_input_idx += 1;
                if s.seq_input_idx == s.input_list.len() {
                    s.seq_input_idx = 0;
                }

                if s.seq_input_idx >= s.num_old_inputs {
                    s.num_old_inputs = s.seq_input_idx + 1;
                }
                s.cur_input_idx = s.seq_input_idx;
            }
        };

        // Get current input info
        let input_info = unsafe { s.input_list.get_unchecked(s.cur_input_idx) };

        s.orig_buf.clear();
        // If content is inlined in the input info
        if let Some(contents) = &input_info.contents {
            for chunk in &contents.chunks {
                s.orig_buf.extend_from_slice(chunk);
            }
        } else {
            // Lets read contents from disk
            let p = match &input_info.path {
                Some(p) => p.as_path(),
                None => {
                    core.error(&format!(
                        "input[{}] has no content or path info !",
                        s.cur_input_idx
                    ));
                    return Err(From::from("No input contents".to_string()));
                }
            };
            // Open file
            let mut fin = match File::open(p) {
                Ok(f) => f,
                _ => return Err(From::from("No input contents".to_string())),
            };
            // Read contents
            if fin.read_to_end(&mut s.orig_buf).is_err() {
                return Err(From::from("No input contents".to_string()));
            }
        }
        //core.trace("Select new input");
    } else {
        //core.trace("Restored previous input");
    }

    // Copy orig into fuzz_buf
    s.fuzz_buf.clear();
    s.fuzz_buf.extend_from_slice(&s.orig_buf);

    // Make fuzz_buf new input
    s.cur_input.chunks.clear();
    s.cur_input.chunks.push(s.fuzz_buf.as_mut_slice());

    Ok(())
}

// Unload and free our resources
fn destroy(
    _core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let _ctx = box_take!(plugin_ctx, State);

    // Remove our store entries
    store.remove(STORE_INPUT_IDX).unwrap();
    store.remove(STORE_INPUT_BYTES).unwrap();
    store.remove(STORE_RESTORE_INPUT).unwrap();
    store.remove(STORE_INPUT_PRIORITY).unwrap();

    Ok(())
}
