// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

//! Implementation of facilities communicating with `ThumbTraceEmulator`.

use std::collections::VecDeque;

use anyhow::Result;
use unicorn_engine::{RegisterARM, Unicorn};

use crate::leakage::LeakageModel;
use crate::trace_emulator::{hook_force_return, ThumbTraceEmulator, ThumbTraceEmulatorTrait};

pub trait Communication {
    fn write(&mut self, data: Vec<u8>);
}

/// Adapter for SimpleSerial protocol over TCP Socket.
/// ChipWhisperer™ is using
/// [SimpleSerial](https://github.com/newaetech/chipwhisperer/blob/develop/software/chipwhisperer/capture/targets/SimpleSerial2.py)
/// as easy communication protocol over UART.
///
/// ThumbTraceEmulator can leverage binaries using SimpleSerial with this
/// adapter to establish communication over TCP Socket.
#[derive(Debug)]
pub struct SimpleSerial {
    data: VecDeque<u8>,
}

impl SimpleSerial {
    pub fn new() -> Self {
        Self {
            data: VecDeque::new(),
        }
    }

    pub fn install_hooks<'a: 'b, 'b, L: LeakageModel>(
        emu: &mut Unicorn<'a, ThumbTraceEmulator<'b, L, SimpleSerial>>,
    ) -> Result<()> {
        emu.register_hook("init_uart", Self::hook_init_uart)?;
        emu.register_hook("getch", Self::hook_getch)?;
        Ok(())
    }

    pub fn hook_init_uart<L: LeakageModel>(
        emu: &mut Unicorn<ThumbTraceEmulator<L, SimpleSerial>>,
    ) -> bool {
        hook_force_return(emu);
        true
    }

    pub fn hook_getch<L: LeakageModel>(
        emu: &mut Unicorn<ThumbTraceEmulator<L, SimpleSerial>>,
    ) -> bool {
        let inner = emu.get_data_mut();
        while inner.victim_com.data.is_empty() {
            if !inner.process_inter_thread_communication() {
                return false;
            }
        }

        let char = inner.victim_com.data.pop_front().unwrap();
        emu.reg_write(RegisterARM::R0, char as u64).unwrap();
        hook_force_return(emu);
        true
    }
}

impl Communication for SimpleSerial {
    fn write(&mut self, data: Vec<u8>) {
        self.data = VecDeque::from(data);
    }
}
