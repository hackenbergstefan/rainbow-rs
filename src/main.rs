// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use std::path::Path;

use clap::Parser;
use log::LevelFilter;

mod asmutils;
mod communication;
mod error;
mod leakage;
mod trace_emulator;

#[derive(Parser, Debug)]
#[command(version)]
struct CmdlineArgs {
    /// Path to elffile to read from
    #[arg(value_parser = file_exists)]
    elffile: String,
    /// Host and port of communication socket
    #[arg(short, long, default_value = "127.0.0.1:1234")]
    socket: String,
    /// Record specific number of samples per trace.
    /// If not given all instructions between `trigger_high()` and `trigger_low()` are recorded.
    #[arg(long)]
    samples: Option<u32>,
    /// Verbosity: `-v`: Info, `-vv`: Debug, `-vvv`: Trace
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,
}

fn file_exists(s: &str) -> Result<String, String> {
    if Path::new(s).exists() {
        Ok(s.into())
    } else {
        Err(format!("File `{s}` does not exist."))
    }
}

fn main() {
    let args = CmdlineArgs::parse();
    simple_logger::SimpleLogger::new()
        .with_level(match args.verbose {
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            3 => LevelFilter::Trace,
            _ => LevelFilter::Warn,
        })
        .init()
        .unwrap();

    let mut emu = trace_emulator::new_simpleserialsocket_stm32f4(
        &args.elffile,
        leakage::HammingWeightLeakage::new(),
        &args.socket,
        args.samples,
    )
    .unwrap();
    emu.emu_start(emu.get_data().meminfo.start_address, 0, 0, 0)
        .unwrap();
}
