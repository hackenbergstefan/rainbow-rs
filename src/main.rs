// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use log::LevelFilter;

mod asmutils;
mod communication;
mod error;
mod leakage;
mod trace_emulator;

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .init()
        .unwrap();

    let mut emu = trace_emulator::new_simpleserialsocket_stm32f4(
        "./_generic_simpleserial-CWLITEARM.elf",
        leakage::HammingWeightLeakage::new(),
        "127.0.0.1:1234",
    )
    .unwrap();
    emu.emu_start(emu.get_data().meminfo.start_address, 0, 0, 0)
        .unwrap();

    for (ins, data) in emu.get_data().trace.iter() {
        println!(
            "{:} {:} {:}",
            ins.mnemonic().unwrap(),
            ins.op_str().unwrap(),
            data
        );
    }
}
