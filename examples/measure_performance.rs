// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use std::{
    io::{BufRead, BufReader, BufWriter, Write},
    net::TcpStream,
    process::Command,
    thread,
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};
use thousands::Separable;

/// Marshaled result of `simpleserial_write(0x01, b"")`
const SIMPLESERIAL_DATA: [u8; 6] = [2, 1, 1, 2, 6, 0];

/// Enum holding commands for communication with rainbow-rs
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum SocketCommand {
    /// Request to receive the last captured trace.
    GetTrace(usize),
    /// Answer to `GetTrace`.
    Trace(Vec<f32>),
    /// Data to be passed to "victim".
    VictimData(Vec<u8>),
}

fn measure(prog: &str, runs: usize, threads: usize) -> (u128, usize) {
    let mut prog = Command::new("cargo")
        .arg("run")
        .arg("--release")
        .arg("--bin=rainbow-rs")
        .arg("--quiet")
        .arg("--")
        .arg("--leakage=elmo")
        .arg(format!("--threads={:}", threads))
        .arg(prog)
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(500));

    let mut samples_read = 0usize;
    let now = SystemTime::now();
    {
        let stream = TcpStream::connect(("127.0.0.1", 6666)).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut writer = BufWriter::new(&stream);
        let mut reader = BufReader::new(&stream);
        for _ in 0..runs {
            writer
                .write_all(format!("{{ \"VictimData\": {:?} }}\n", SIMPLESERIAL_DATA).as_bytes())
                .unwrap();
            writer.flush().unwrap();
        }

        for _ in 0..runs {
            writer
                .write_all(format!("{{ \"GetTrace\": {:} }}\n", 0).as_bytes())
                .unwrap();
            writer.flush().unwrap();
            let mut buf = String::new();
            reader.read_line(&mut buf).unwrap();
            if let SocketCommand::Trace(trace) = serde_json::from_str(&buf).unwrap() {
                samples_read += trace.len();
            }
        }
    }
    let elapsed = now.elapsed().unwrap().as_millis();
    prog.kill().unwrap();

    (elapsed, samples_read)
}

macro_rules! measure {
    ($prog:expr, $runs:expr, $threads:expr) => {
        let (time, total_samples) = measure($prog, $runs, $threads);
        println!(
            "{:35}: {:>6} loops using {:2} threads => {:10} ms - {:>20} samples, {:>10} samples/s",
            $prog,
            $runs.separate_with_commas(),
            $threads,
            time,
            total_samples.separate_with_commas(),
            (total_samples as f32 / (time as f32) * 1000.0)
                .round()
                .separate_with_commas()
        );
    };
}

fn main() {
    // Compile current project
    Command::new("cargo")
        .arg("build")
        .arg("--release")
        .output()
        .unwrap();

    let num_cpu = num_cpus::get();

    // Start measurements
    measure!("examples/cwlitearm_xor.elf", 1, 1);
    measure!("examples/cwlitearm_xor.elf", 10000, 1);
    measure!("examples/cwlitearm_xor.elf", 10000, num_cpu / 2);
    measure!("examples/cwlitearm_xor.elf", 10000, num_cpu);

    measure!("examples/cwlitearm_loop_1000.elf", 1, 1);
    measure!("examples/cwlitearm_loop_1000.elf", 1000, 1);
    measure!("examples/cwlitearm_loop_1000.elf", 1000, num_cpu / 2);
    measure!("examples/cwlitearm_loop_1000.elf", 1000, num_cpu);
    measure!("examples/cwlitearm_loop_1000.elf", 10000, num_cpu / 2);
    measure!("examples/cwlitearm_loop_1000.elf", 10000, num_cpu);

    measure!("examples/cwlitearm_loop_10000.elf", 1, 1);
    measure!("examples/cwlitearm_loop_10000.elf", 1000, 1);
    measure!("examples/cwlitearm_loop_10000.elf", 1000, num_cpu / 2);
    measure!("examples/cwlitearm_loop_10000.elf", 1000, num_cpu);
    measure!("examples/cwlitearm_loop_10000.elf", 10000, num_cpu / 2);
    measure!("examples/cwlitearm_loop_10000.elf", 10000, num_cpu);

    measure!("examples/cwlitearm_loop_100000.elf", 1, 1);
    measure!("examples/cwlitearm_loop_100000.elf", 100, 1);
    measure!("examples/cwlitearm_loop_100000.elf", 100, num_cpu / 2);
    measure!("examples/cwlitearm_loop_100000.elf", 100, num_cpu);

    measure!("examples/cwlitearm_loop_1000000.elf", 1, 1);
    measure!("examples/cwlitearm_loop_1000000.elf", 10, 1);
    measure!("examples/cwlitearm_loop_1000000.elf", 10, num_cpu / 2);
    measure!("examples/cwlitearm_loop_1000000.elf", 10, num_cpu);
    measure!("examples/cwlitearm_loop_1000000.elf", 100, num_cpu / 2);
    measure!("examples/cwlitearm_loop_1000000.elf", 100, num_cpu);
}
