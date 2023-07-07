// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

//! Implementation of facilities communicating with `ThumbTraceEmulator`.

use unicorn_engine::{RegisterARM, Unicorn};

use crate::leakage::LeakageModel;
use crate::trace_emulator::hook_force_return;
use crate::trace_emulator::ThumbTraceEmulator;
use crate::Command;

pub trait Communication {}

/// Adapter for SimpleSerial protocol over TCP Socket.
/// ChipWhisperer™ is using
/// [SimpleSerial](https://github.com/newaetech/chipwhisperer/blob/develop/software/chipwhisperer/capture/targets/SimpleSerial2.py)
/// as easy communication protocol over UART.
///
/// ThumbTraceEmulator can leverage binaries using SimpleSerial with this
/// adapter to establish communication over TCP Socket.
#[derive(Debug)]
pub struct SimpleSerial {}

impl SimpleSerial {
    pub fn hook_init_uart<'a, L: LeakageModel>(
        emu: &mut Unicorn<'a, ThumbTraceEmulator<L, SimpleSerial>>,
    ) -> bool {
        hook_force_return(emu);
        true
    }

    pub fn hook_getch<'a, L: LeakageModel>(
        emu: &mut Unicorn<'a, ThumbTraceEmulator<L, SimpleSerial>>,
    ) -> bool {
        if let Command::VictimDataByte(d) = emu.get_data_mut().itc.victim.recv() {
            emu.reg_write(RegisterARM::R0, d as u64).unwrap();
            hook_force_return(emu);
            return true;
        }
        false
    }
}

impl Communication for SimpleSerial {}
