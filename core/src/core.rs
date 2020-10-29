use ::cflib::*;
use ::log::*;
use ::shared_memory::ShmemConf;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

use crate::Result;

use crate::config::*;
use crate::plugin::*;
use crate::stats::*;
use crate::store::*;

pub struct CfCore<'a> {
    /// Information pulled from the input config file
    pub config: Config,
    /// Set to true when an exit event happens (ctrl-c)
    pub exiting: Arc<AtomicBool>,
    /// The shared memory mapping used for stats
    pub shmem: shared_memory::Shmem,
    /// Data available to plugins
    pub ctx: PluginCtx<'a>,
    /// List of loaded plugins
    pub plugin_chain: Vec<Plugin>,
    /// Index of the first plugin of the fuzz loop
    pub fuzz_loop_start: usize,
    pub stats: CoreStats,
    /// Public plugin data store
    pub store: Store,
}

impl<'a> CfCore<'a> {
    pub fn init(mut config: Config) -> Result<Pin<Box<Self>>> {
        info!(
            "Allocating space for fuzzer statistics '{}'",
            config.stats_file
        );
        let shmem = match config.shmem.take() {
            Some(s) => s,
            None => {
                match ShmemConf::new()
                    .flink(&config.stats_file)
                    .size(config.shmem_size)
                    .create()
                {
                    Ok(m) => m,
                    Err(e) => {
                        return Err(From::from(format!(
                            "Failed to create shared memory mapping of size {} with error : {:?}",
                            config.shmem_size, e
                        )))
                    }
                }
            }
        };

        info!("Loading plugins");
        let fuzz_loop_start_idx = config.pre_fuzz_loop.len();
        let mut plugin_data = Vec::with_capacity(fuzz_loop_start_idx + config.fuzz_loop.len());
        let mut plugin_chain: Vec<Plugin> =
            Vec::with_capacity(fuzz_loop_start_idx + config.fuzz_loop.len());

        if fuzz_loop_start_idx > 0 {
            debug!("Loading pre_fuzz_loop plugins");
            for f_path in &config.pre_fuzz_loop {
                let cur_plugin: Plugin = Plugin::new(&f_path)?;
                //debug!("\t{}", cur_plugin.name());
                plugin_data.push(PluginData::new(cur_plugin.name()));
                plugin_chain.push(cur_plugin);
            }
        }

        debug!("Loading fuzz_loop plugins");
        for f_path in &config.fuzz_loop {
            let cur_plugin: Plugin = Plugin::new(&f_path)?;
            //info!("\t- {}", cur_plugin.name());
            plugin_data.push(PluginData::new(cur_plugin.name()));
            plugin_chain.push(cur_plugin);
        }
        info!("Loaded {} plugin(s)", plugin_chain.len());

        let buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(shmem.as_ptr(), shmem.len()) };

        let mut core = Box::pin(CfCore {
            config,
            exiting: Arc::new(AtomicBool::new(false)),
            stats: CoreStats::default(),
            ctx: PluginCtx {
                plugin_data,
                stats: Stats::new(buf)?,
                cur_plugin_id: plugin_chain.len(),
            },
            plugin_chain,
            fuzz_loop_start: fuzz_loop_start_idx,
            shmem,
            store: Store::default(),
        });

        core.init_stats()?;
        core.init_public_store();
        Ok(core)
    }

    pub fn exiting(&self) -> bool {
        self.exiting.load(Ordering::Relaxed)
    }

    pub fn init_plugins(&mut self) -> Result<()> {
        info!("Initializing plugins");
        let num_plugins = self.plugin_chain.len();
        // Call init()
        for plugin_id in 0..num_plugins {
            if self.exiting.load(Ordering::Relaxed) {
                self.ctx.cur_plugin_id = num_plugins;
                return Err(From::from(format!(
                    "CTRL-C while initializing plugins ({}/{} initialized)",
                    plugin_id, num_plugins
                )));
            }
            self.ctx.cur_plugin_id = plugin_id;

            let plugin: &mut Plugin =
                unsafe { self.plugin_chain.get_unchecked_mut(self.ctx.cur_plugin_id) };

            // Add new plugin to stats
            self.ctx.stats.new_plugin(plugin.name())?;
            // Every plugin gets an exec_time
            plugin.exec_time = match self.ctx.stats.new_stat(
                &format!(
                    "{}exec_time{}",
                    cflib::TAG_PREFIX_AVG,
                    cflib::TAG_POSTFIX_NS
                ),
                NewStat::Num(0),
            ) {
                Ok(StatVal::Num(v)) => v,
                Err(e) => {
                    return Err(From::from(format!(
                        "Failed to create exec_time stat for {} : {}",
                        plugin.name(),
                        e
                    )))
                }
                _ => panic!("Returned ok with invalid stat type"),
            };

            debug!("\t\"{}\"->load()", plugin.name());
            if let Err(e) = plugin.init(&mut self.ctx, &mut self.store.content) {
                warn!("Error initializing \"{}\"", plugin.name());
                return Err(e);
            }
        }

        // Call validate()
        for plugin_id in 0..num_plugins {
            if self.exiting.load(Ordering::Relaxed) {
                self.ctx.cur_plugin_id = num_plugins;
                return Err(From::from(format!(
                    "CTRL-C while running plugin validation ({}/{} validated)",
                    plugin_id, num_plugins
                )));
            }
            self.ctx.cur_plugin_id = plugin_id;
            let plugin: &mut Plugin =
                unsafe { self.plugin_chain.get_unchecked_mut(self.ctx.cur_plugin_id) };

            debug!("\t\"{}\"->validate()", plugin.name());
            if let Err(e) = plugin.validate(&mut self.ctx, &mut self.store.content) {
                return Err(e);
            }
        }
        // Init is done
        self.ctx.stats.set_state(CoreState::Fuzzing);
        self.ctx.cur_plugin_id = num_plugins;

        Ok(())
    }

    pub fn destroy_plugins(&mut self) {
        debug!("Destroying plugins");
        let num_plugins = self.plugin_chain.len();
        for (plugin_id, plugin) in self.plugin_chain.iter_mut().rev().enumerate() {
            if !plugin.is_init {
                continue;
            }
            self.ctx.cur_plugin_id = num_plugins - 1 - plugin_id;
            debug!("\"{}\"->unload()", plugin.name());
            if let Err(e) = plugin.destroy(&mut self.ctx, &mut self.store.content) {
                warn!("Error destroying \"{}\" : {}", plugin.name(), e);
            }
        }
        self.ctx.cur_plugin_id = num_plugins;
    }

    ///Runs all plugins once
    pub fn single_run(&mut self) -> Result<()> {
        let core_start: Instant = Instant::now();
        let mut plugin_start: Instant;
        let mut time_elapsed: u64;
        let mut total_plugin_time: u64 = 0;
        let num_plugins = self.plugin_chain.len();

        self.ctx.cur_plugin_id = 0;

        *self.stats.num_execs.val += 1;
        self.store.avg_denominator += 1;

        info!("Running through all plugins once");
        for (plugin_id, plugin) in self.plugin_chain.iter_mut().enumerate() {
            self.ctx.cur_plugin_id = plugin_id;

            if self.exiting.load(Ordering::Relaxed) {
                self.ctx.cur_plugin_id = num_plugins;
                return Err(From::from(format!(
                    "CTRL-C while testing plugins (about to call '{}')",
                    plugin.name()
                )));
            }

            debug!("\t\"{}\"->fuzz()", plugin.name());

            plugin_start = Instant::now();
            plugin.do_work(&mut self.ctx, &mut self.store.content)?;
            time_elapsed = plugin_start.elapsed().as_nanos() as u64;

            total_plugin_time += time_elapsed;

            //Adjust the plugin's exec_time average
            cflib::update_average(
                plugin.exec_time.val,
                time_elapsed,
                *self.stats.num_execs.val,
            );
            debug!("\tTime : {} ns", *plugin.exec_time.val);

            self.ctx.cur_plugin_id += 1;
        }

        self.ctx.cur_plugin_id = num_plugins;

        //Adjust the core's exec_time average
        time_elapsed = core_start.elapsed().as_nanos() as u64;
        cflib::update_average(
            self.stats.total_exec_time.val,
            time_elapsed,
            *self.stats.num_execs.val,
        );
        cflib::update_average(
            self.stats.exec_time.val,
            time_elapsed - total_plugin_time,
            *self.stats.num_execs.val,
        );
        debug!("\tCore time : {} us", *self.stats.exec_time.val);

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

        // This is the real fuzz loop, make sure it is as fast as possible
        loop {
            core_start = Instant::now();
            total_plugin_time = 0;

            *self.stats.num_execs.val += 1;
            if self.store.avg_denominator < 20 {
                self.store.avg_denominator += 1;
            }

            self.ctx.cur_plugin_id = self.fuzz_loop_start;
            for plugin in fuzz_loop_plugins.iter_mut() {
                // run the plugin
                plugin_start = Instant::now();
                plugin.do_work(&mut self.ctx, &mut self.store.content)?;
                time_elapsed = plugin_start.elapsed().as_nanos() as u64;
                // Update plugin's exec time
                cflib::update_average(
                    plugin.exec_time.val,
                    time_elapsed,
                    self.store.avg_denominator,
                );
                // Keep track of time spent in plugins
                total_plugin_time += time_elapsed;
                self.ctx.cur_plugin_id += 1;
            }

            // Check if ctrl-c has been hit
            if self.exiting.load(Ordering::Relaxed) {
                self.ctx.cur_plugin_id = num_plugins;
                return Err(From::from("CTRL-C while fuzzing".to_string()));
            }

            time_elapsed = core_start.elapsed().as_nanos() as u64;
            // Update average full iteration time
            cflib::update_average(
                self.stats.total_exec_time.val,
                time_elapsed,
                self.store.avg_denominator,
            );

            // Update core's exec time
            cflib::update_average(
                self.stats.exec_time.val,
                time_elapsed - total_plugin_time,
                self.store.avg_denominator,
            );
        }
    }
}

impl<'a> Drop for CfCore<'a> {
    fn drop(&mut self) {
        self.clear_public_store();

        for (k, _v) in self.store.content.drain() {
            error!("store['{}'] hasn't been free'd", k);
        }
    }
}
