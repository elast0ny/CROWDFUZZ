use std::mem::MaybeUninit;

pub use ::afl_lib::*;
pub use ::cflib::*;

mod mutators;
pub use mutators::*;
mod bit_flip;
pub use bit_flip::*;
mod arithmetic;
pub use arithmetic::*;
mod interesting;
pub use interesting::*;
mod havoc;
pub use havoc::*;

cflib::register!(name, env!("CARGO_PKG_NAME"));
cflib::register!(load, init);
cflib::register!(pre_fuzz, validate);
cflib::register!(fuzz, mutate_input);
cflib::register!(unload, destroy);

struct State {
    force_update: bool,
    /// Used to notice when the input changes
    prev_input_idx: usize,
    /// Buffer to hold the current stage name
    stage_name: String,
    /// State info for the current mutator stage
    cur_stage: MutatorStage,
    /// Stage name that lives in the fuzzer stats memory
    stat_cur_stage: StatStr,
    /// Stage iterations that lives in the fuzzer stats memory
    stat_num_iterations: StatNum,

    restore_input: &'static mut bool,
    no_select: &'static mut bool,
    no_mutate: &'static bool,

    inputs: &'static Vec<CfInputInfo>,
    cur_input_idx: &'static usize,
    cur_input: &'static mut CfInput,
    afl_vars: &'static mut AflGlobals,
    afl_queue: &'static mut AflQueue,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let state = Box::new(unsafe {
        State {
            force_update: true,
            prev_input_idx: 0,
            stage_name: String::new(),
            cur_stage: MutatorStage::default(),
            // Stats
            stat_cur_stage: core.new_stat_str("stage", 128, "[init]")?,
            stat_num_iterations: core.new_stat_num("iterations", 0)?,
            // Core store values
            restore_input: store.as_mutref(STORE_RESTORE_INPUT, Some(core))?,
            no_select: store.as_mutref(STORE_NO_SELECT, Some(core))?,
            no_mutate: store.as_mutref(STORE_NO_MUTATE, Some(core))?,

            // Plugin store values
            inputs: MaybeUninit::zeroed().assume_init(),
            cur_input_idx: MaybeUninit::zeroed().assume_init(),
            cur_input: MaybeUninit::zeroed().assume_init(),
            afl_vars: MaybeUninit::zeroed().assume_init(),
            afl_queue: MaybeUninit::zeroed().assume_init(),
        }
    });

    Ok(Box::into_raw(state) as _)
}

// Make sure we have everything to fuzz properly
fn validate(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let state = box_ref!(plugin_ctx, State);

    // Grab all the keys we need to function
    unsafe {
        state.inputs = store.as_mutref(STORE_INPUT_LIST, Some(core))?;
        state.cur_input_idx = store.as_ref(STORE_INPUT_IDX, Some(core))?;
        state.cur_input = store.as_mutref(STORE_INPUT_BYTES, Some(core))?;

        match store.as_mutref(STORE_AFL_GLOBALS, None) {
            Ok(v) => state.afl_vars = v,
            Err(e) => {
                core.warn("Missing AFL globals ! Is the `afl_state` plugin running ?");
                return Err(e);
            }
        };
        state.afl_queue = store.as_mutref(STORE_AFL_QUEUE, Some(core))?;
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

    if *s.no_mutate {
        if !s.force_update {
            s.stat_cur_stage.set("None");
            *s.stat_num_iterations.val = 0;
            s.force_update = true;
        }
        return Ok(());
    }

    let stage = &mut s.cur_stage;
    let input = &mut s.cur_input;
    let afl = &mut s.afl_vars;
    let q = unsafe { s.afl_queue.get_unchecked_mut(*s.cur_input_idx) };

    // Update stage name if we switched input
    if s.force_update || s.prev_input_idx != *s.cur_input_idx {
        // Reset stage
        stage.sync_to_input(q, afl, input);
        // Update stage name
        stage.update_info(&mut s.stage_name, s.stat_num_iterations.val);
        s.stat_cur_stage.set(&s.stage_name);

        s.prev_input_idx = *s.cur_input_idx;
        s.force_update = false;
    }

    // Mutate the input
    loop {
        match stage.mutate(input) {
            StageResult::WillRestoreInput => {
                // The mutator will restore the testcase
                *s.no_select = true;
                *s.restore_input = false;
            }
            StageResult::CantRestoreInput => {
                // Mutator cant restore original testcase
                *s.restore_input = true;
                *s.no_select = false;
            }
            StageResult::Update => {
                // Update cur_stage stat
                stage.update_info(&mut s.stage_name, s.stat_num_iterations.val);
                s.stat_cur_stage.set(&s.stage_name);
                // Loop again to mutate at least once
                continue;
            }
            StageResult::Done => {
                // Can we progress to the next stage ?
                if stage.next(q, afl, input) {
                    continue;
                }
                // Pick a new testcase
                *s.restore_input = false;
                *s.no_select = false;
            }
        };

        //core.trace(&format!("{:?}", state.cur_input.chunks[0]));
        break;
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
