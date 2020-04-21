use ::crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ::sysinfo::{ProcessorExt, SystemExt};
use ::tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::*,
    Frame, Terminal,
};
use std::borrow::Cow;
use std::{
    error::Error,
    io::{stdout, Stdout, Write},
};

use crate::*;

pub struct UiState<'a> {
    pub state: &'a mut State,

    /// Tab header state
    pub header_title: String,
    /// Currently selected fuzzer tab
    pub selected_tab: usize,
    /// Index of the selected plugin for the overview window
    pub overview_plugin_idx: usize,
    
    /// The height required to show fuzzer stats & plugin list
    pub fuzzer_stats_heigth: usize,
    /// The width required to show the fuzzer name and stat titles
    pub max_core_stat_title: usize,
    /// The width required for the select plugin list titles
    pub max_plugin_name: usize,
    /// The width required to show plugin details (plugin bname and plugin stats titles)
    pub max_plugin_stat_title: usize,

    /// List of strings that constitute the footer
    pub footer: Vec<String>,
    /// Index of the CPU string in `footer`
    pub footer_cpu_idx: usize,
    /// Index of the MEM string in `footer`
    pub footer_mem_idx: usize,
}

impl<'a> UiState<'a> {
    pub fn new(state: &'a mut State) -> Self {
        let mut footer = Vec::new();
        footer.push("Load [Cpu ".to_owned());
        let footer_cpu_idx = footer.len();
        footer.push("000%".to_owned());
        footer.push(", Mem ".to_owned());
        let footer_mem_idx = footer.len();
        footer.push("000%".to_owned());
        footer.push("]".to_owned());

        let fuzzer_stats_heigth = 0;
        let max_core_stat_title = 0;
        let max_plugin_stat_title = 0;
        let max_plugin_name = 0;

        let mut state = Self {
            state,
            header_title: String::from("Fuzzers (0)"),
            selected_tab: 0,
            overview_plugin_idx: 0,
            fuzzer_stats_heigth,
            max_core_stat_title,
            max_plugin_name,
            max_plugin_stat_title,
            footer,
            footer_cpu_idx,
            footer_mem_idx
        };

        state.update_fuzzers();
        state
    }

    pub fn update_cached_values(&mut self) {
        use std::fmt::Write;
        
        self.header_title.clear();
        let num_fuzzers = self.state.fuzzers.len();
        let _ = write!(self.header_title, "Fuzzers ({})", num_fuzzers);
        
        // Make sure the tab selection is within bounds
        if self.selected_tab > num_fuzzers {
            self.selected_tab = num_fuzzers;
        }

        // If no more fuzzer, reset cached max lengths
        if num_fuzzers == 0 {
            self.fuzzer_stats_heigth = 0;
            self.max_core_stat_title = 0;
            self.max_plugin_stat_title = 0;
            self.max_plugin_name = 0;
        // If we havent computed the max lengths yet
        } else if self.max_core_stat_title == 0 {

            // Get longest fuzzer name
            for fuzzer in self.state.fuzzers.iter() {
                if self.max_core_stat_title < fuzzer.pretty_name.len() {
                    self.max_core_stat_title = fuzzer.pretty_name.len();
                }
            }
            let fuzzer = &self.state.fuzzers[0];

            // longest list between core stats and plugin list
            if fuzzer.core.stats.len() > fuzzer.plugins.len() {
                self.fuzzer_stats_heigth = fuzzer.core.stats.len();
            } else {
                self.fuzzer_stats_heigth = fuzzer.plugins.len();
            }

            for stat in fuzzer.core.stats.iter() {
                // Get longest fuzzer stat name
                if self.max_core_stat_title < stat.get_tag().len() {
                    self.max_core_stat_title = stat.get_tag().len();
                }
            }

            for plugin in fuzzer.plugins.iter() {
                // Longest plugin name
                if self.max_plugin_name < plugin.name.len() {
                    self.max_plugin_name = plugin.name.len();
                }
                // Longest plugin stat name
                for stat in plugin.stats.iter() {
                    if self.max_plugin_stat_title < stat.get_tag().len() {
                        self.max_plugin_stat_title = stat.get_tag().len();
                    }
                }
            }            
            
            // If plugin name is longer than the longest stat title
            if self.max_plugin_name > self.max_plugin_stat_title {
                self.max_plugin_stat_title = self.max_plugin_name;
            }
        }
    }

    pub fn update_footer(&mut self, cpu_load: usize, mem_load: usize) {
        use std::fmt::Write;
        let cpu_str = &mut self.footer[self.footer_cpu_idx];
        cpu_str.clear();
        let _ = write!(cpu_str, "{:02}%", cpu_load);

        let mem_str = &mut self.footer[self.footer_mem_idx];
        mem_str.clear();
        let _ = write!(mem_str, "{:02}%", mem_load);
    }

    pub fn update_fuzzers(&mut self) {
        self.state.update_fuzzers();
        if self.state.changed {
            self.update_cached_values();
            self.state.changed = false;
        }
    }

    pub fn select_next_fuzzer(&mut self) {
        self.selected_tab += 1;
        if self.selected_tab == self.state.fuzzers.len() + 1 {
            self.selected_tab = 0;
        }
    }

    pub fn select_prev_fuzzer(&mut self) {
        if self.selected_tab == 0 {
            self.selected_tab = self.state.fuzzers.len();
        } else {
            self.selected_tab -= 1;
        }
    }

    pub fn select_next_plugin(&mut self) {
        let num_plugins: usize;
        let idx: &mut usize;
        
        if self.state.fuzzers.len() == 0 {
            return;
        } else if self.selected_tab == 0 {
            num_plugins = self.state.fuzzers[0].plugins.len();
            idx = &mut self.overview_plugin_idx;
        } else {
            let cur_fuzzer = &mut self.state.fuzzers[self.selected_tab - 1];
            num_plugins = cur_fuzzer.plugins.len();
            idx = &mut cur_fuzzer.cur_plugin_idx;
        }

        *idx += 1;
        if *idx == num_plugins {
            *idx = 0;
        }
    }

    pub fn select_prev_plugin(&mut self) {
        let num_plugins: usize;
        let idx: &mut usize;
        
        if self.state.fuzzers.len() == 0 {
            return;
        } else if self.selected_tab == 0 {
            num_plugins = self.state.fuzzers[0].plugins.len();
            idx = &mut self.overview_plugin_idx;
        } else {
            let cur_fuzzer = &mut self.state.fuzzers[self.selected_tab - 1];
            num_plugins = cur_fuzzer.plugins.len();
            idx = &mut cur_fuzzer.cur_plugin_idx;
        }

        if *idx == 0 {
            *idx = num_plugins - 1;
        } else {
            *idx -= 1;
        }
    }

    pub fn draw_self<B: Backend>(ui: &mut UiState, mut f: Frame<B>) {
        //Call methods on the ui object
        ui.draw(&mut f);
    }

    pub fn draw<B: Backend>(&mut self, f: &mut Frame<B>) {
        let size = f.size();
        // Split terminal into 3 main parts
        let rects = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(3),
                    Constraint::Length(size.height - 4),
                    Constraint::Length(1),
                ]
                .as_ref(),
            )
            .split(size);

        // Draw main sections
        let (header_rect, content_rect, footer_rect) = (rects[0], rects[1], rects[2]);
        self.draw_header(f, header_rect);
        self.draw_fuzzer(f, content_rect);
        self.draw_footer(f, footer_rect);
    }

    /// Renders selectable tabs
    pub fn draw_header<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let fuzzer_tab_titles = std::iter::once("All")
            .chain(self.state.fuzzers.iter().map(|f| f.core.name.as_str()))
            .collect::<Vec<&str>>();
        
        let mut fuzzer_tabs = Tabs::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(&self.header_title),
            )
            .highlight_style(Style::default().fg(Color::Yellow))
            .titles(&fuzzer_tab_titles)
            .select(self.selected_tab);
        f.render(&mut fuzzer_tabs, area);
    }

    /// Draws the view when a fuzzer is selected
    pub fn draw_fuzzer<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let cur_fuzzer;
        let selected_plugin_idx;
        let cur_tab_name: &str;

        // Overview
        if self.selected_tab == 0 {
            let fuzzer_details = Block::default().borders(Borders::ALL).title("Overview");
            selected_plugin_idx = self.overview_plugin_idx;
            if self.state.fuzzers.len() == 0 {
                let text = &[Text::raw(Cow::from("<No fuzzers>"))];
                let mut content = Paragraph::new(text.iter())
                    .block(fuzzer_details)
                    .style(Style::default().fg(Color::Red))
                    .alignment(tui::layout::Alignment::Center)
                    .wrap(false);
                f.render(&mut content, area);
                return;
            }
            
            // Refresh stat values
            for fuzzer in self.state.fuzzers.iter_mut() {
                // Refresh main fuzzer stats
                fuzzer.refresh(false);
                // Refresh stats for selected plugin
                fuzzer.refresh_plugin(selected_plugin_idx);
            }
            
            // Merge stats
            let (head, tail) = self.state.fuzzers.split_at_mut(1);
            // Fuzzer stats
            Plugin::combine_stats(&mut head[0].core, &tail.iter().map(|f| &f.core).collect::<Vec<&Plugin>>(), None);
            // Plugin stats
            for (idx, plugin) in head[0].plugins.iter_mut().enumerate() {
                let plugin_list = &tail.iter().map(|f| &f.plugins[idx]).collect::<Vec<&Plugin>>();
                if idx == selected_plugin_idx {
                    Plugin::combine_stats(plugin, plugin_list, None);
                } else {
                    Plugin::combine_stats(plugin, plugin_list, Some(COMPONENT_EXEC_TIME_IDX));
                }
            }
            cur_fuzzer = &mut self.state.fuzzers[0];
            cur_tab_name = "Overview"
        // Specific fuzzer selected
        } else {
            cur_fuzzer = &mut self.state.fuzzers[self.selected_tab - 1];
            selected_plugin_idx = cur_fuzzer.cur_plugin_idx;
            // Refresh fuzzer stats
            cur_fuzzer.refresh(false);
            // Refresh stats for selected plugin
            cur_fuzzer.refresh_plugin(selected_plugin_idx);
            cur_tab_name = cur_fuzzer.pretty_name.as_str();
        }

        let plugin_details_rect;
        
        // Render the top view (fuzzer stats and plugin list)
        {
            let mut max_fuzzer_val = 0;
            let mut fuzzer_titles = Vec::new();
            let mut fuzzer_vals = Vec::new();
            for s in cur_fuzzer.core.stats.iter_mut() {                
                let (tag, val) = s.get_tuple();
                fuzzer_titles.push(Text::Raw(Cow::from(tag)));
                if val.len() > max_fuzzer_val {
                    max_fuzzer_val = val.len();
                }
                fuzzer_vals.push(Text::Raw(Cow::from(val)));
            }

            // split total area into subsections
            let details_rect = area;
            let rects = Layout::default()
                .direction(Direction::Vertical)
                .constraints(
                    [
                        Constraint::Length((self.fuzzer_stats_heigth + 2) as u16),
                        Constraint::Percentage(100),
                    ]
                    .as_ref(),
                )
                .split(details_rect);
            let core_details_rect = rects[0];
            plugin_details_rect = rects[1];
            let rects = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Length((self.max_core_stat_title + 2) as u16),
                        Constraint::Length((max_fuzzer_val + 1) as u16),
                        Constraint::Length((self.max_plugin_name + 3) as u16),
                        Constraint::Percentage(100),
                    ]
                    .as_ref(),
                )
                .split(core_details_rect);
            let core_tag_list_rect = rects[0];
            let core_val_list_rect = rects[1];
            let plugins_list_rect = rects[2];
            let plugins_time_rect = rects[3];

            // Render fuzzer stat titles
            let mut core_tag_list = List::new(fuzzer_titles.drain(..))
                .block(
                    Block::default()
                        .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
                        .title(cur_tab_name),
                );
            f.render(&mut core_tag_list, core_tag_list_rect);
            // Render fuzzer stat values
            let mut core_val_list = List::new(fuzzer_vals.drain(..))
                .block(Block::default().borders(Borders::TOP | Borders::BOTTOM));
            f.render(&mut core_val_list, core_val_list_rect);

            // Render list of plugin names
            let mut plugin_names: Vec<&str> = Vec::with_capacity(cur_fuzzer.plugins.len());
            let mut plugin_times: Vec<&str> = Vec::with_capacity(cur_fuzzer.plugins.len());
            for plugin in cur_fuzzer.plugins.iter_mut() {
                plugin_names.push(plugin.name.as_str());
                plugin_times.push(plugin.stats[COMPONENT_EXEC_TIME_IDX].val_as_str());
            }
            let mut plugin_list = SelectableList::default()
                .block(
                    Block::default()
                        .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
                        .title("Plugins"),
                )
                .items(&plugin_names)
                .select(Some(selected_plugin_idx))
                .highlight_symbol(">")
                .highlight_style(Style::default().fg(Color::Yellow).modifier(Modifier::BOLD));
            f.render(&mut plugin_list, plugins_list_rect);
            // Render each average exec time for the plugin list
            let mut plugin_times = SelectableList::default()
                .block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::RIGHT))
                .items(&plugin_times)
                .select(Some(selected_plugin_idx))
                .highlight_style(Style::default().fg(Color::Yellow).modifier(Modifier::BOLD));
            f.render(&mut plugin_times, plugins_time_rect);
        }
    
        // Render the selected plugin details
        {
            let cur_plugin = &mut cur_fuzzer.plugins[selected_plugin_idx];       

            let mut _max_plugin_val = 0;
            let mut plugin_titles = Vec::new();
            let mut plugin_vals = Vec::new();
            for s in cur_plugin.stats.iter_mut() {                
                let (tag, val) = s.get_tuple();
                plugin_titles.push(Text::Raw(Cow::from(tag)));
                if val.len() > _max_plugin_val {
                    _max_plugin_val = val.len();
                }
                plugin_vals.push(Text::Raw(Cow::from(val)));
            }
            
            // Split bottom area for currently selected plugin
            let rects = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Length((self.max_plugin_stat_title + 2) as u16),
                        Constraint::Percentage(100),
                    ]
                    .as_ref(),
                )
                .split(plugin_details_rect);
            let plugin_tag_list_rect = rects[0];
            let plugin_val_list_rect = rects[1];

            // Render selected plugin stat names
            let mut plugin_tag_list = List::new(plugin_titles.drain(..))
                .block(
                    Block::default()
                        .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
                        .title(cur_plugin.name.as_ref()),
                );
            f.render(&mut plugin_tag_list, plugin_tag_list_rect);
            // Render selected plugin stat values
            let mut plugin_val_list = List::new(plugin_vals.drain(..))
                .block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::RIGHT));
            f.render(&mut plugin_val_list, plugin_val_list_rect);
        }
    }

    pub fn draw_footer<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
    
        self.state.sys_info.refresh_cpu();
        self.state.sys_info.refresh_memory();
        let cpu_speed = self.state
            .sys_info
            .get_processors()
            .iter()
            .fold(0f32, |t, c| t + c.get_cpu_usage()) as usize
            / self.state.sys_info.get_processors().len();
        let mem_usage = ((self.state.sys_info.get_used_memory() * 100) / self.state.sys_info.get_total_memory()) as usize;
        self.update_footer(cpu_speed, mem_usage);
    
        // Apply color to cpu and mem
        let footer = self.footer.iter().enumerate().map(|(idx, s)| {
            if idx == self.footer_cpu_idx {
                Text::styled(s, 
                if cpu_speed > 90 {
                    Style::default().fg(Color::Red)
                } else if cpu_speed > 75 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Green)
                })
            } else if idx == self.footer_mem_idx {
                Text::styled(s, 
                if mem_usage > 90 {
                    Style::default().fg(Color::Red)
                } else if mem_usage > 75 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Green)
                })
            } else {
                Text::raw(s)
            }
        }).collect::<Vec<Text>>();
    
        let mut bottom_stats = Paragraph::new(footer.iter())
            //.style(Style::default())
            //.alignment(Alignment::Center)
            .wrap(false);
    
        f.render(&mut bottom_stats, area);
    }
}

pub fn init_ui() -> Result<Terminal<CrosstermBackend<Stdout>>, Box<dyn Error>> {
    // Setup the UI
    enable_raw_mode()?;
    let mut stdout = stdout();
    #[allow(deprecated)]
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;
    Ok(terminal)
}

pub fn destroy_ui() -> Result<(), Box<dyn Error>> {
    #[allow(deprecated)]
    execute!(stdout(), LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}



