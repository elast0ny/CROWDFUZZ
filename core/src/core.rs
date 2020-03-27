use std::boxed::Box;
use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::pin::Pin;
use std::ptr::null_mut;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

use ::log::*;
use ::shared_memory::*;

use crate::Result;

use crate::config::*;
use crate::interface::*;
use crate::plugin::*;
use crate::stats::*;

pub struct Core {
    /// Information pulled from the input config file
    pub config: Config,
    /// Set to true when an exit event happens (ctrl-c)
    pub exiting: Arc<AtomicBool>,
    /// Statistic about the fuzzer that live in the shared memory
    pub stats: CoreStats,

    /// current plugin being executed
    pub cur_plugin_id: usize,
    /// List of loaded plugins
    pub plugin_chain: Vec<Plugin>,
    /// Index of the first plugin of the fuzz loop
    pub fuzz_loop_start: usize,

    /// Public plugin data store
    pub store: HashMap<String, VecDeque<*mut c_void>>,

    ///Holds context information available to plugins
    pub core_if: cflib::CoreInterface,
}

impl Core {
    pub fn init(prefix: &str, config_path: &str) -> Result<Pin<Box<Core>>> {
        info!("Loading project config");
        let config = Config::new(prefix, config_path)?;

        info!(
            "Allocating space for fuzzer statistics '{}'",
            config.stats_file
        );
        let shmem = match SharedMemConf::default()
            .set_link_path(&config.stats_file)
            .set_size(config.shmem_size)
            .create()
        {
            Ok(m) => m,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to create shared memory mapping of size {} with error : {:?}",
                    config.shmem_size, e
                )))
            }
        };

        info!("Loading plugins");
        let fuzz_loop_start_idx = config.pre_fuzz_loop.len();
        let mut plugin_chain: Vec<Plugin> =
            Vec::with_capacity(fuzz_loop_start_idx + config.fuzz_loop.len());

        if fuzz_loop_start_idx > 0 {
            debug!("Loading pre_fuzz_loop plugins");
            for f_path in &config.pre_fuzz_loop {
                let cur_plugin: Plugin = Plugin::new(&f_path)?;
                debug!("\t{}", cur_plugin.name());
                plugin_chain.push(cur_plugin);
            }
        }

        debug!("Loading fuzz_loop plugins");
        for f_path in &config.fuzz_loop {
            let cur_plugin: Plugin = Plugin::new(&f_path)?;
            info!("\t- {}", cur_plugin.name());
            plugin_chain.push(cur_plugin);
        }
        info!("Loaded {} plugin(s)", plugin_chain.len());

        let mut core = Box::pin(Core {
            config: config,
            stats: CoreStats::new(shmem),

            exiting: Arc::new(AtomicBool::new(false)),

            cur_plugin_id: plugin_chain.len(),
            plugin_chain: plugin_chain,
            store: HashMap::new(),
            fuzz_loop_start: fuzz_loop_start_idx,

            core_if: cflib::CoreInterface {
                priv_data: null_mut(),
                store_push_back: Some(store_push_back_cb),
                store_push_front: Some(store_push_front_cb),
                store_pop_back: Some(store_pop_back_cb),
                store_pop_front: Some(store_pop_front_cb),
                store_get_mut: Some(store_get_mut_cb),
                store_len: Some(store_len_cb),
                add_stat: Some(add_stat_cb),
                log: Some(log_cb),
                ctx: null_mut(),
            },
        });

        //Link the opaque core ptr for the plugin interface callbacks
        core.core_if.ctx = (&(*core)) as *const Core as *const _;

        core.init_public_store();
        core.init_stats();

        return Ok(core);
    }

    pub fn init_public_store(&mut self) {
        self.store_push_front(
            String::from(cflib::KEY_INPUT_DIR_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.input))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_STATE_DIR_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.state))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_RESULT_DIR_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.results))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_TARGET_PATH_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.target))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_CWD_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.cwd))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_CUR_INPUT_PATH_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.input_file_name))) as *mut _ as _,
        );
        let mut tmp_list = Vec::with_capacity(self.config.target_args.len());
        for arg in &self.config.target_args {
            tmp_list.push(Box::leak(Box::new(cflib::CTuple::from_utf8(arg))) as *mut _ as _);
        }
        for arg in &tmp_list {
            self.store_push_back(String::from(cflib::KEY_TARGET_ARGS_STR), *arg);
        }
    }

    pub fn clear_public_store(&mut self) {
        // Free up resources taken our store keys
        let mut tmp_ptr: *mut cflib::CTuple;
        unsafe {
            let _: Box<cflib::CTuple> = Box::from_raw(self.store_pop_front(cflib::KEY_INPUT_DIR_STR) as *mut _);
            let _: Box<cflib::CTuple> = Box::from_raw(self.store_pop_front(cflib::KEY_STATE_DIR_STR) as *mut _);
            let _: Box<cflib::CTuple> = Box::from_raw(self.store_pop_front(cflib::KEY_RESULT_DIR_STR) as *mut _);
            let _: Box<cflib::CTuple> =
                Box::from_raw(self.store_pop_front(cflib::KEY_TARGET_PATH_STR) as *mut _);
            let _: Box<cflib::CTuple> = Box::from_raw(self.store_pop_front(cflib::KEY_CWD_STR) as *mut _);
            let _: Box<cflib::CTuple> =
                Box::from_raw(self.store_pop_front(cflib::KEY_CUR_INPUT_PATH_STR) as *mut _);

            while !{
                tmp_ptr = self.store_pop_front(cflib::KEY_TARGET_ARGS_STR) as _;
                tmp_ptr
            }
            .is_null()
            {
                Box::from_raw(tmp_ptr);
            }
        }
    }

    pub fn init_stats(&mut self) {
        self.stats.init(&self.config);
    }

    pub fn exiting(&self) -> bool {
        self.exiting.load(Ordering::Relaxed)
    }

    pub fn init_plugins(&mut self) -> Result<()> {
        info!("Initializing plugins");

        // Call init()
        for plugin_id in 0..self.plugin_chain.len() {
            if self.exiting.load(Ordering::Relaxed) {
                return Err(From::from(format!(
                    "CTRL-C while initializing plugins ({}/{} initialized)",
                    plugin_id,
                    self.plugin_chain.len()
                )));
            }
            self.cur_plugin_id = plugin_id;

            let plugin: &mut Plugin =
                unsafe { self.plugin_chain.get_unchecked_mut(self.cur_plugin_id) };

            self.stats.add_component(Some(plugin));

            debug!("\t\"{}\"->init()", plugin.name());
            if let Err(e) = plugin.init(&mut self.core_if) {
                warn!("Error initializing \"{}\"", plugin.name());
                return Err(e);
            }

            plugin.priv_data = self.core_if.priv_data;
            self.core_if.priv_data = null_mut();
        }

        // Call validate()
        for plugin_id in 0..self.plugin_chain.len() {
            if self.exiting.load(Ordering::Relaxed) {
                return Err(From::from(format!(
                    "CTRL-C while running plugin validation ({}/{} validated)",
                    plugin_id,
                    self.plugin_chain.len()
                )));
            }
            self.cur_plugin_id = plugin_id;
            let plugin: &mut Plugin =
                unsafe { self.plugin_chain.get_unchecked_mut(self.cur_plugin_id) };

            debug!("\t\"{}\"->validate()", plugin.name());
            if let Err(e) = plugin.validate(&mut self.core_if) {
                warn!("Error while \"{}\".validate()", plugin.name());
                return Err(e);
            }
        }

        self.cur_plugin_id = self.plugin_chain.len();
        Ok(())
    }

    pub fn destroy_plugins(&mut self) {
        debug!("Destroying plugins");
        for (plugin_id, plugin) in self.plugin_chain.iter().rev().enumerate() {
            if !plugin.init_called {
                continue;
            }
            self.cur_plugin_id = self.plugin_chain.len() - 1 - plugin_id;
            debug!("\"{}\"->destroy()", plugin.name());
            if let Err(e) = plugin.destroy(&mut self.core_if) {
                warn!("Error destroying \"{}\" : {}", plugin.name(), e);
            }
        }
        self.cur_plugin_id = self.plugin_chain.len();
    }

    ///Runs all plugins once
    pub fn single_run(&mut self) -> Result<()> {
        let core_start: Instant = Instant::now();
        let mut plugin_start: Instant;
        let mut time_elapsed: u64;
        let mut total_plugin_time: u64 = 0;
        let num_plugins = self.plugin_chain.len();

        self.cur_plugin_id = 0;
        *self.stats.state = cflib::CORE_FUZZING;
        *self.stats.num_execs += 1;
        info!("Running through all plugins once");
        for plugin in self.plugin_chain.iter_mut() {
            if self.exiting.load(Ordering::Relaxed) {
                self.cur_plugin_id = num_plugins;
                *self.stats.state = cflib::CORE_EXITING;
                return Err(From::from(format!(
                    "CTRL-C while testing plugins (about to call '{}')",
                    plugin.name()
                )));
            }

            debug!("\t\"{}\"->work()", plugin.name());

            plugin_start = Instant::now();
            plugin.do_work(&mut self.core_if)?;
            time_elapsed = plugin_start.elapsed().as_micros() as u64;
            total_plugin_time += time_elapsed;

            //Adjust the plugin's exec_time average
            *plugin.exec_time = plugin
                .exec_time
                .wrapping_add(time_elapsed.wrapping_sub(*plugin.exec_time) / *self.stats.num_execs);
            debug!("\tTime : {} us", *plugin.exec_time);

            self.cur_plugin_id += 1;
        }

        self.cur_plugin_id = num_plugins;

        //Adjust the core's exec_time average
        time_elapsed = core_start.elapsed().as_micros() as u64 - total_plugin_time;
        *self.stats.exec_time = self
            .stats
            .exec_time
            .wrapping_add(time_elapsed.wrapping_sub(*self.stats.exec_time) / *self.stats.num_execs);
        debug!("\tCore time : {} us", *self.stats.exec_time);

        info!("Ready to go !");
        Ok(())
    }

    pub fn fuzz_loop(&mut self) -> Result<()> {
        info!("Fuzzing...");
        let num_plugins = self.plugin_chain.len();
        let (_, fuzz_loop_plugins) = self.plugin_chain.split_at_mut(self.fuzz_loop_start);
        let mut core_start: Instant;
        let mut plugin_start: Instant;
        let mut time_elapsed: u64;
        let mut total_plugin_time: u64;

        loop {
            core_start = Instant::now();
            total_plugin_time = 0;
            *self.stats.num_execs += 1;

            self.cur_plugin_id = self.fuzz_loop_start;

            for plugin in fuzz_loop_plugins.iter_mut() {
                if self.exiting.load(Ordering::Relaxed) {
                    self.cur_plugin_id = num_plugins;
                    *self.stats.state = cflib::CORE_EXITING;
                    return Err(From::from(format!(
                        "CTRL-C while fuzzing (about to call '{}')",
                        plugin.name()
                    )));
                }

                plugin_start = Instant::now();
                plugin.do_work(&mut self.core_if)?;
                time_elapsed = plugin_start.elapsed().as_micros() as u64;
                total_plugin_time += time_elapsed;

                //Adjust the plugin's exec_time average
                *plugin.exec_time = plugin.exec_time.wrapping_add(
                    time_elapsed.wrapping_sub(*plugin.exec_time) / *self.stats.num_execs,
                );
                self.cur_plugin_id += 1;
            }

            //if *self.stats.num_execs == 2 {
            //    return Ok(());
            //}

            //Adjust the core's exec_time average
            time_elapsed = core_start.elapsed().as_micros() as u64 - total_plugin_time;
            *self.stats.exec_time = self.stats.exec_time.wrapping_add(
                time_elapsed.wrapping_sub(*self.stats.exec_time) / *self.stats.num_execs,
            );
        }
    }
}

impl Drop for Core {
    fn drop(&mut self) -> () {
        self.clear_public_store();

        for (key, vec) in self.store.iter() {
            if vec.len() != 0 {
                error!("Store key '{}' has {} leaked item(s)...", key, vec.len());
            }
        }
    }
}
