use ::clap::{App, Arg};
use ::crossterm::event::{poll, read, Event, KeyCode};
use ::sysinfo::{RefreshKind, System, SystemExt};

use std::collections::HashSet;
use std::error::Error;
use std::time::{Duration, Instant};

pub mod ui;
use crate::ui::*;
pub mod state;
use crate::state::*;

fn main() -> Result<(), Box<dyn Error>> {
    let args = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("A terminal based ui for CROWDFUZZ fuzzers")
        .arg(
            Arg::with_name("state_dir")
                .short("s")
                .long("state_dir")
                .help("Path to a fuzzer's state directory")
                .required(true)
                .multiple(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("fuzzer_prefix")
                .long("fuzzer_prefix")
                .help("Sets the fuzzer prefix")
                .default_value("fuzzer_stats_")
                .hidden(true) //This shouldnt really be needed by anyone
                .takes_value(true),
        )
        .arg(
            Arg::with_name("stats_prefix")
                .long("stats_prefix")
                .help("Sets the fuzzer stats file prefix")
                .default_value("fuzzer_stats_")
                .hidden(true) //This shouldnt really be needed by anyone
                .takes_value(true),
        )
        .arg(
            Arg::with_name("refresh_rate")
                .short("r")
                .long("refresh_rate")
                .help("The refresh rate for the UI in ms")
                .default_value("500")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("dir_scan_rate")
                .short("d")
                .long("dir_scan_rate")
                .help("The rate at which to scan state directories in ms")
                .default_value("2000")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();
    let dir_scan_rate: Duration = Duration::from_millis(
        args.value_of("dir_scan_rate")
            .unwrap()
            .parse()
            .expect("Invalid number specified for --dir_scan_rate"))
    ;
    let refresh_rate: Duration = Duration::from_millis(
        args.value_of("refresh_rate")
            .unwrap()
            .parse()
            .expect("Invalid number specified for --refresh_rate"),
    );

    let mut state = State {
        unique_fuzzers: HashSet::new(),
        fuzzers: Vec::new(),
        fuzzer_prefix: String::from(args.value_of("fuzzer_prefix").unwrap()),
        stat_file_prefix: String::from(args.value_of("stats_prefix").unwrap()),
        monitored_dirs: args
            .values_of("state_dir")
            .unwrap()
            .map(|d| String::from(d))
            .collect::<Vec<String>>(),
        sys_info: System::new_with_specifics(
            RefreshKind::new().with_processes().with_cpu().with_memory(),
        ),
        tab_titles: Vec::new(),
        changed: true,
    };
    state.sys_info.refresh_cpu();
    state.sys_info.refresh_memory();

    let mut ui = UiState::new(&mut state);

    let mut terminal = init_ui()?;
    
    let mut last_scan = Instant::now();
    let status: Result<(), Box<dyn Error>>;
    loop {
        // Scan fuzzer directories
        if last_scan.elapsed() > dir_scan_rate {
            ui.update_fuzzers();
            last_scan = Instant::now();
        }
        // refresh the UI
        terminal.draw(|f| UiState::draw_self(&mut ui, f))?;

        if poll(refresh_rate)? {
            let read_evt = match read() {
                Ok(e) => e,
                Err(e) => {
                    status = Err(Box::new(e));
                    break;
                }
            };
            match read_evt {
                Event::Key(event) => {
                    match event.code {
                        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                            status = Ok(());
                            break;
                        }
                        KeyCode::F(5) => {
                            ui.update_fuzzers();
                        }
                        KeyCode::Tab | KeyCode::PageUp | KeyCode::Right => {
                            ui.select_next_fuzzer();
                        }
                        KeyCode::PageDown | KeyCode::Left => {
                            ui.select_prev_fuzzer();
                        }
                        KeyCode::Up => {
                            ui.select_prev_plugin();
                        }
                        KeyCode::Down => {
                            ui.select_next_plugin();
                        }
                        _ => {}
                    };
                }
                _ => { /*trigger refresh for any unhandled event*/ }
            }
        }
    }

    destroy_ui()?;
    status
}
