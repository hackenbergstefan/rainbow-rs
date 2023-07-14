// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use std::{
    io::{BufRead, BufReader, BufWriter, Read, Write},
    net::TcpListener,
    path::Path,
    thread,
    time::Duration,
};

use anyhow::Result;
use clap::Parser;
use log::LevelFilter;
use serde::{Deserialize, Serialize};

use rainbow_rs::{
    asmutils::ElfInfo,
    itc::{create_inter_thread_channels, BiChannel, ITCRequest, ITCResponse},
    leakage::HammingWeightLeakage,
    new_simpleserialsocket_stm32f4, ThumbTraceEmulatorTrait,
};

#[derive(Parser, Debug)]
#[command(version)]
struct CmdlineArgs {
    /// Path to elffile to read from
    #[arg(value_parser = file_exists)]
    elffile: String,
    /// Host and port of communication socket
    #[arg(short, long, default_value = "127.0.0.1:6666")]
    socket: String,
    /// Record specific number of samples per trace.
    /// If not given all instructions between `trigger_high()` and `trigger_low()` are recorded.
    #[arg(long)]
    samples: Option<u32>,
    /// Number of threads
    #[arg(long, default_value = "1")]
    threads: u32,
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

/// Enum holding commands for communication with rainbow-rs
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Command {
    /// Request to receive the last captured trace.
    GetTrace(usize),
    /// Answer to `GetTrace`.
    Trace(Vec<f32>),
    /// Data to be passed to "victim".
    VictimData(Vec<u8>),
}

/// Establish communication with rainbow-rs.
/// Communication is entirely json based over one socket with the host
/// sending requests and rainbow-rs answering.
fn listen_forever(socket_address: &str, itc: BiChannel<ITCRequest, ITCResponse>) -> Result<()> {
    let listener = TcpListener::bind(socket_address)?;
    let (stream, _) = listener.accept()?;
    stream.set_nodelay(true)?;
    let stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);

    for line in stream_reader.lines() {
        let command: Command = serde_json::from_str(&line?)?;
        match command {
            Command::VictimData(data) => {
                itc.send(ITCRequest::VictimData(data))?;
            }
            Command::GetTrace(samples) => match itc.recv()? {
                ITCResponse::Trace(mut trace) => {
                    while samples > 0 && trace.len() > samples {
                        trace.pop();
                    }
                    while trace.len() < samples {
                        trace.push(0.0);
                    }

                    stream_writer
                        .write_all(serde_json::to_string(&Command::Trace(trace))?.as_bytes())?;
                    stream_writer.write_all(b"\n")?;
                    stream_writer.flush()?;
                }
            },
            _ => todo!(),
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = CmdlineArgs::parse();
    simple_logger::SimpleLogger::new()
        .with_level(match args.verbose {
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            3 => LevelFilter::Trace,
            _ => LevelFilter::Warn,
        })
        .init()?;

    let mut buf = Vec::new();
    std::fs::File::open(&args.elffile)?.read_to_end(&mut buf)?;

    let (server, client) = create_inter_thread_channels();
    let elfinfo = ElfInfo::new(&buf)?;
    thread::scope(|scope| -> Result<()> {
        let threads = Vec::from_iter((0..args.threads).map(|_| {
            let s = scope.spawn(|| -> Result<()> {
                let mut emu = new_simpleserialsocket_stm32f4(
                    &elfinfo,
                    HammingWeightLeakage::new(),
                    client.clone(),
                )?;
                emu.start()?;
                Ok(())
            });
            s
        }));
        thread::sleep(Duration::from_millis(100));

        for t in threads {
            if t.is_finished() {
                return t.join().unwrap();
            }
        }

        listen_forever(&args.socket, server)?;
        Ok(())
    })?;
    Ok(())
}

#[cfg(test)]
mod test_parser {
    use super::*;

    #[test]
    fn test_args() {
        use clap::CommandFactory;
        CmdlineArgs::command().debug_assert();
    }

    #[test]
    fn test_non_existing_file() {
        assert!(CmdlineArgs::try_parse_from([&"./foo.elf"].iter()).is_err())
    }
}
