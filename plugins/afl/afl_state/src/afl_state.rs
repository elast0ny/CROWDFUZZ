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
    afl: AflGlobals,
    queue: AflQueue,
    max_cal: u8,
    is_calibrating: bool,
    prev_idx: usize,
    first_trace: Vec<u8>,
    tmp: String,
    init_testcase_num: usize,

    queued_with_cov: StatNum<'_>,
    queued_variable: StatNum<'_>,

    num_execs: &'static u64,
    no_select: &'static mut bool,
    no_mutate: &'static mut bool,

    inputs: &'static Vec<CfInputInfo>,
    input_idx: &'static usize,
    input_priority: &'static mut BinaryHeap<InputPriority>,
    prev_exec_time_ns: &'static u64,
    trace_bits: Option<&'static Vec<u8>>,
}

// Initialize our plugin
fn init(core: &mut dyn PluginInterface, store: &mut CfStore) -> Result<*mut u8> {
    #[allow(invalid_value)]
    let mut s = Box::new(unsafe {
        State {
            afl: AflGlobals::default(),
            queue: Vec::new(),
            is_calibrating: false,
            prev_idx: 0,
            max_cal: 0,
            first_trace: Vec::with_capacity(MAP_SIZE),
            tmp: String::new(),
            init_testcase_num: 0,

            // Stats
            queued_with_cov: core
                .new_stat_num(&format!("{}queued_with_cov", TAG_PREFIX_TOTAL), 0)?,
            queued_variable: core
                .new_stat_num(&format!("{}queued_variable", TAG_PREFIX_TOTAL), 0)?,
            // Core store vals
            num_execs: store.as_ref(STORE_NUM_EXECS, Some(core))?,
            no_select: store.as_mutref(STORE_NO_SELECT, Some(core))?,
            no_mutate: store.as_mutref(STORE_NO_MUTATE, Some(core))?,
            // Plugin store vals
            inputs: MaybeUninit::zeroed().assume_init(),
            input_idx: MaybeUninit::zeroed().assume_init(),
            input_priority: MaybeUninit::zeroed().assume_init(),
            prev_exec_time_ns: MaybeUninit::zeroed().assume_init(),
            trace_bits: None,
        }
    });

    store.insert_exclusive(STORE_AFL_GLOBALS, &s.afl, Some(core))?;
    store.insert_exclusive(STORE_AFL_QUEUE, &s.queue, Some(core))?;

    let plugin_conf: &HashMap<String, String>;
    unsafe { plugin_conf = store.as_ref(STORE_PLUGIN_CONF, Some(core))? }

    s.load_conf(plugin_conf)?;

    s.max_cal = if s.afl.fast_cal { 3 } else { CAL_CYCLES };

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
        s.input_idx = store.as_ref(STORE_INPUT_IDX, Some(core))?;
        s.input_priority = store.as_mutref(STORE_INPUT_PRIORITY, Some(core))?;
        s.prev_exec_time_ns = store.as_mutref(STORE_TARGET_EXEC_TIME, Some(core))?;
        if let Ok(v) = store.as_ref(STORE_AFL_TRACE_BITS, None) {
            s.trace_bits = Some(v);
        } else {
            core.warn("No plugin gathering instrumentation...");
        }
    }

    s.init_testcase_num = s.inputs.len();
    s.queue.reserve(s.inputs.len());
    Ok(())
}

// Perform our task in the fuzzing loop
fn update_state(
    core: &mut dyn PluginInterface,
    store: &mut CfStore,
    plugin_ctx: *mut u8,
) -> Result<()> {
    let s = box_ref!(plugin_ctx, State);

    // If there are new/never calibrated inputs
    if s.inputs.len() > s.queue.len() {
        let mut val = AflQueueEntry::default();
        val.cal_left = s.max_cal;
        val.handicap = *s.num_execs - 1;
        s.queue.resize(s.inputs.len(), val);
    }

    // Process calibration info from last run
    if s.is_calibrating {
        let mut first_cal = false;
        let q = unsafe { s.queue.get_unchecked_mut(s.prev_idx) };
        s.prev_idx = *s.input_idx;
        s.is_calibrating = false;

        let prev_exec_us = *s.prev_exec_time_ns / 1000;
        s.afl.total_cal_us += prev_exec_us;
        s.afl.total_cal_cycles += 1;

        if q.cal_left == s.max_cal {
            first_cal = true;
        } else if q.cal_left == s.max_cal + 1 {
            // Skip over max_cals so we dont think its first cal run
            q.cal_left -= 1;
        }

        q.cal_left -= 1;

        /* Save calib results */
        // Update queue entry
        update_average(&mut q.exec_us, prev_exec_us, (s.max_cal - q.cal_left) as _);
        if let Some(trace_bits) = s.trace_bits {
            // If its first calib run and no instrumentation
            if !s.afl.dumb_mode && first_cal && count_bytes(trace_bits) == 0 {
                core.error("Testcase did not trigger any coverage ?!");
                return Err(From::from("No instrumentation".to_string()));
            }

            let cksum = hash32(trace_bits, HASH_CONST);

            if first_cal {
                s.first_trace.clear();
                s.first_trace.extend_from_slice(&trace_bits);
                q.exec_cksum = cksum;
                q.bitmap_size = count_bytes(trace_bits);
                s.afl.total_bitmap_size += q.bitmap_size as u64;
                s.afl.total_bitmap_entries += 1;
                *s.queued_with_cov.val += 1;

                let hnb = has_new_bits(&mut s.afl.virgin_bits, trace_bits);
                if hnb == 0 {
                    core.warn("Testcase does not provide any new coverage");
                } else {
                    q.has_new_cov = true;
                }
            } else if q.exec_cksum != cksum {
                // Set new variable bytes
                for i in 0..s.afl.var_bytes.len() {
                    unsafe {
                        if *s.afl.var_bytes.get_unchecked(i) == 0
                            && *s.first_trace.get_unchecked(i) != *trace_bits.get_unchecked(i)
                        {
                            *s.afl.var_bytes.get_unchecked_mut(i) = 1;
                        }
                    }
                }
                // Mark as variable
                if !q.var_behavior {
                    core.warn("Testcase produces different coverage");
                    q.var_behavior = true;
                    *s.queued_variable.val += 1;
                    *s.queued_with_cov.val -= 1;
                    q.cal_left = CAL_CYCLES_LONG + 1;
                }
            }
        }

        /* Restore normal fuzzing */
        if q.cal_left == 0 {
            // We are still in dry-run phase
            if s.init_testcase_num > 0 {
                // Print some stats for the last testcase we just finished calibrating
                let input_info = unsafe { s.inputs.get_unchecked(*s.input_idx) };
                use std::fmt::Write;
                s.tmp.clear();
                if let Some(ref p) = input_info.path {
                    let _ = write!(&mut s.tmp, "{}", p.to_str().unwrap());
                } else {
                    let _ = write!(&mut s.tmp, "{:?}", input_info.uid);
                }
                let _ = write!(
                    &mut s.tmp,
                    " len {}, map size = {}, exec speed = {} us",
                    input_info.len, q.bitmap_size, q.exec_us
                );
                core.info(&s.tmp);

                // If last input of dry-run
                s.init_testcase_num -= 1;
                if s.init_testcase_num == 0 {
                    s.show_init_stats(core, store);
                }
            }
            *s.no_mutate = false;
        }
    }

    // Setup calibration for current iteration if required
    let q = unsafe { s.queue.get_unchecked_mut(*s.input_idx) };
    if q.cal_left > 0 {
        s.is_calibrating = true;
        // Disable mutation for this iteration
        *s.no_mutate = true;

        // More than one cal left, also reuse input for next iteration
        if q.cal_left > 1 {
            *s.no_select = true;
        } else {
            *s.no_select = false;
        }
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
    /// Parse config values and sets their equivalent in AflState
    pub fn load_conf(&mut self, plugin_conf: &HashMap<String, String>) -> Result<()> {

        if plugin_conf.get("afl_skip_deterministic").is_some() {
            self.afl.skip_deterministic = true;
        }
        
        Ok(())
    }

    pub fn show_init_stats(&mut self, core: &mut dyn PluginInterface, store: &CfStore) {
        use std::fmt::Write;
        let mut max_len: usize = 0;
        let mut min_bm: usize = usize::MAX;
        let mut max_bm: usize = 0;
        let mut min_exec: usize = usize::MAX;
        let mut max_exec: usize = 0;

        for (idx, q) in self.queue.iter().enumerate() {
            if q.cal_left != 0 {
                continue;
            }
            let input_info = unsafe { self.inputs.get_unchecked(idx) };

            if input_info.len > max_len {
                max_len = input_info.len;
            }
            if max_bm < q.bitmap_size as usize {
                max_bm = q.bitmap_size as usize;
            }
            if min_bm > q.bitmap_size as usize {
                min_bm = q.bitmap_size as usize;
            }

            if max_exec < q.exec_us as usize {
                max_exec = q.exec_us as usize;
            }
            if min_exec > q.exec_us as usize {
                min_exec = q.exec_us as usize;
            }
        }
        self.tmp.clear();
        core.info("All test cases processed.");
        pub const AFL_PERF_LINE: &str = " See afl-fuzz/docs/perf_tips.txt";

        // Check exec speed
        if let Ok(avg_ns) = unsafe { store.as_ref::<u64>(STORE_AVG_TARGET_EXEC_TIME, Some(core)) } {
            if *avg_ns > 10_000_000 {
                let _ = write!(
                    &mut self.tmp,
                    "The target binary is pretty slow ({} us) !",
                    *avg_ns / 1000
                );
                if *avg_ns > 50_000_000 {
                    self.afl.havoc_div = 10;
                } else {
                    self.afl.havoc_div = 5;
                }
            }
            if !self.tmp.is_empty() {
                self.tmp.push_str(AFL_PERF_LINE);
                core.warn(&self.tmp);
                self.tmp.clear();
            }
        }
        // Check input size
        if max_len > 50 * 1024 {
            let _ = write!(&mut self.tmp, "Some test cases are huge ({}) !", max_len);
        } else if max_len > 10 * 1024 {
            let _ = write!(&mut self.tmp, "Some test cases are big ({}) !", max_len);
        }
        if !self.tmp.is_empty() {
            self.tmp.push_str(AFL_PERF_LINE);
            core.warn(&self.tmp);
            self.tmp.clear();
        }

        if self.inputs.len() > 100 {
            core.warn("You probably have far too many input files! Consider trimming down.");
        } else if self.inputs.len() > 20 {
            core.warn("You have lots of input files; try starting small.");
        }
        let _ = write!(&mut self.tmp, "Here are some useful stats:\n\n");
        let _ = writeln!(
            &mut self.tmp,
            "    Test case count : {} favored, {} variable, {} total",
            *self.queued_with_cov.val,
            *self.queued_variable.val,
            self.inputs.len()
        );
        if self.afl.total_bitmap_entries == 0 {
            self.tmp.push_str("       Bitmap range : <Not available>\n");
        } else {
            let _ = writeln!(
                &mut self.tmp,
                "       Bitmap range : {} to {} bits (average: {} bits)",
                min_bm,
                max_bm,
                self.afl.total_bitmap_size / self.afl.total_bitmap_entries
            );
        }

        let _ = writeln!(
            &mut self.tmp,
            "        Exec timing : {} to {} us (average: {} us)",
            min_exec,
            max_exec,
            self.afl.total_cal_us / self.afl.total_cal_cycles
        );
        core.info(&self.tmp);
        core.info("All set and ready to roll!");
    }
}
