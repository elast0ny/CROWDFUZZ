use std::error::Error;
use std::time::{Duration, Instant};

use clap::{App, Arg};
use crossterm::event::{poll, read, Event, KeyCode, KeyModifiers};
use env_logger::Env;

pub mod ui;
use crate::ui::*;
pub mod state;
use crate::state::*;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("A terminal based ui for CROWDFUZZ fuzzers")
        .arg(
            Arg::with_name("project_state")
                .help("Path to a fuzzer's state directory")
                .short("-s")
                .required(true)
                .takes_value(true)
                //.multiple(true).number_of_values(1)
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
            .expect("Invalid number specified for --dir_scan_rate"),
    );
    let refresh_rate: Duration = Duration::from_millis(
        args.value_of("refresh_rate")
            .unwrap()
            .parse()
            .expect("Invalid number specified for --refresh_rate"),
    );

    let mut state = State::new(&mut args);
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
                        //also allow ctrl-c
                        KeyCode::Char('c') | KeyCode::Char('C') => {
                            if event.modifiers.contains(KeyModifiers::CONTROL) {
                                status = Ok(());
                                break;
                            }
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
