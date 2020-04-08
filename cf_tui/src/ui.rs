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
    pub header_title_num: usize,
    pub header_title: String,
    pub selected_tab: usize,

    pub core_stat_tags: Vec<String>,
    pub plugin_stat_tags: Vec<String>,

    pub footer: Vec<String>,
    pub footer_cpu_idx: usize,
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

        let mut state = Self {
            state,
            header_title_num: 0,
            header_title: String::from("Fuzzers (0)"),
            selected_tab: 0,
            core_stat_tags: Vec::new(),
            plugin_stat_tags: Vec::new(),
            footer,
            footer_cpu_idx,
            footer_mem_idx 
        };

        state.update_fuzzers();
        state
    }

    pub fn update_cached_values(&mut self) {
        use std::fmt::Write;
        
        // Number of fuzzers has changed
        if self.header_title_num != self.state.fuzzers.len() {
            self.header_title.clear();
            self.header_title_num = self.state.fuzzers.len();
            let _ = write!(self.header_title, "Fuzzers ({})", self.header_title_num);
            
            // Make sure the tab selection is within bounds
            if self.selected_tab > self.header_title_num {
                self.selected_tab = self.header_title_num;
            }
        }
        
        // Get list of stat values
        let mut unique_core_stats: HashSet<String> = HashSet::new();
        let mut unique_plugin_stats: HashSet<String> = HashSet::new();
        self.core_stat_tags.clear();
        self.plugin_stat_tags.clear();
        for fuzzer in self.state.fuzzers.iter() {
            for stat in fuzzer.core.stats.iter() {
                let tag = stat.get_tag();
                if unique_core_stats.contains(stat.get_tag()) {
                    continue;
                }
                unique_core_stats.insert(String::from(tag));
                self.core_stat_tags.push(String::from(tag));
            }
            for plugin in fuzzer.plugins.iter() {
                for stat in plugin.stats.iter() {
                    let tag = stat.get_tag();
                    if unique_plugin_stats.contains(stat.get_tag()) {
                        continue;
                    }
                    unique_plugin_stats.insert(String::from(tag));
                    self.plugin_stat_tags.push(String::from(tag));
                }
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
        if self.selected_tab == 0 {
            return;
        }
        let cur_fuzzer = &mut self.state.fuzzers[self.selected_tab - 1];
        cur_fuzzer.cur_plugin_idx += 1;
        if cur_fuzzer.cur_plugin_idx == cur_fuzzer.plugins.len() {
            cur_fuzzer.cur_plugin_idx = 0;
        }
    }

    pub fn select_prev_plugin(&mut self) {
        if self.selected_tab == 0 {
            return;
        }
        let cur_fuzzer = &mut self.state.fuzzers[self.selected_tab - 1];

        if cur_fuzzer.cur_plugin_idx == 0 {
            cur_fuzzer.cur_plugin_idx = cur_fuzzer.plugins.len() - 1;
        } else {
            cur_fuzzer.cur_plugin_idx -= 1;
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
        if self.selected_tab == 0 {
            self.draw_all(f, content_rect);
        } else {
            self.draw_fuzzer(f, content_rect);
        }
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

    /// Draws the view for total stats for the current fuzzers
    pub fn draw_all<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let fuzzer_details = Block::default().borders(Borders::ALL).title("Overview");

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

        //f.render(&mut fuzzer_details, area);
    }

    /// Draws the view when a fuzzer is selected
    pub fn draw_fuzzer<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
        let cur_fuzzer = &mut self.state.fuzzers[self.selected_tab - 1];
        let core_title = format!("{}({})", cur_fuzzer.core.name, cur_fuzzer.pid);

        // Get longest list between core stats and plugin list
        let mut core_stats_height = cur_fuzzer.core.stats.len();
        if core_stats_height < cur_fuzzer.plugins.len() {
            core_stats_height = cur_fuzzer.plugins.len();
        }
        core_stats_height += 2;

        // Refresh core stats
        cur_fuzzer.refresh(false);
        // Refresh all the plugin exec_times
        for plugin in cur_fuzzer.plugins.iter_mut() {
            plugin.stats[COMPONENT_EXEC_TIME_IDX].update(false);
        }

        // split total area into subsections
        let details_rect = area;
        let rects = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(core_stats_height as u16),
                    Constraint::Percentage(100),
                ]
                .as_ref(),
            )
            .split(details_rect);
        let core_details_rect = rects[0];
        let plugin_details_rect = rects[1];
        let rects = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Length(cur_fuzzer.core.max_tag_len + 2),
                    Constraint::Length(cur_fuzzer.core.max_val_len + 1),
                    Constraint::Length(cur_fuzzer.max_plugin_name_len + 3),
                    Constraint::Percentage(100),
                ]
                .as_ref(),
            )
            .split(core_details_rect);
        let core_tag_list_rect = rects[0];
        let core_val_list_rect = rects[1];
        let plugins_list_rect = rects[2];
        let plugins_time_rect = rects[3];

        // Render fuzzer core stat names
        let mut core_tag_list = List::new(
            cur_fuzzer
                .core
                .stats
                .iter()
                .map(|s| Text::Raw(Cow::from(s.get_tag()))),
        )
        .block(
            Block::default()
                .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
                .title(&core_title),
        );
        f.render(&mut core_tag_list, core_tag_list_rect);
        // Render fuzzer core stat values
        let mut core_val_list = List::new(
            cur_fuzzer
                .core
                .stats
                .iter()
                .map(|s| Text::Raw(Cow::from(s.as_str()))),
        )
        .block(Block::default().borders(Borders::TOP | Borders::BOTTOM));
        f.render(&mut core_val_list, core_val_list_rect);

        // Render list of plugin names
        let mut plugin_names: Vec<&str> = Vec::with_capacity(cur_fuzzer.plugins.len());
        let mut plugin_times: Vec<&str> = Vec::with_capacity(cur_fuzzer.plugins.len());
        for plugin in cur_fuzzer.plugins.iter() {
            plugin_names.push(plugin.name.as_str());
            plugin_times.push(plugin.stats[COMPONENT_EXEC_TIME_IDX].as_str());
        }
        let mut plugin_list = SelectableList::default()
            .block(
                Block::default()
                    .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
                    .title("Plugins"),
            )
            .items(&plugin_names)
            .select(Some(cur_fuzzer.cur_plugin_idx))
            .highlight_symbol(">")
            .highlight_style(Style::default().fg(Color::Yellow).modifier(Modifier::BOLD));
        f.render(&mut plugin_list, plugins_list_rect);
        // Render each average exec time for the plugin list
        let mut plugin_times = SelectableList::default()
            .block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::RIGHT))
            .items(&plugin_times)
            .select(Some(cur_fuzzer.cur_plugin_idx))
            .highlight_style(Style::default().fg(Color::Yellow).modifier(Modifier::BOLD));
        f.render(&mut plugin_times, plugins_time_rect);
        
        // Refresh selected plugin stats
        let cur_plugin = cur_fuzzer.refresh_cur_plugin();       
        
        // Split bottom area for currently selected plugin
        let rects = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Length(cur_plugin.max_tag_len + 2),
                    Constraint::Percentage(100),
                ]
                .as_ref(),
            )
            .split(plugin_details_rect);
        let plugin_tag_list_rect = rects[0];
        let plugin_val_list_rect = rects[1];

        // Render selected plugin stat names
        let mut plugin_tag_list = List::new(
            cur_plugin
                .stats
                .iter()
                .map(|s| Text::Raw(Cow::from(s.get_tag()))),
        )
        .block(
            Block::default()
                .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
                .title(cur_plugin.name.as_ref()),
        );
        f.render(&mut plugin_tag_list, plugin_tag_list_rect);

        // Render selected plugin stat values
        let mut plugin_val_list = List::new(
            cur_plugin
                .stats
                .iter()
                .map(|s| Text::Raw(Cow::from(s.as_str()))),
        )
        .block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::RIGHT));
        f.render(&mut plugin_val_list, plugin_val_list_rect);
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



