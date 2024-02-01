// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

//! Implementation of facilities communicating with `ThumbTraceEmulator`.

use std::collections::VecDeque;

use anyhow::Result;
use unicorn_engine::{RegisterARM, Unicorn};

use crate::{hook_force_return, ThumbTraceEmulator, ThumbTraceEmulatorTrait};

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

    pub fn install_hooks<'a: 'b, 'b>(
        emu: &mut Unicorn<'a, ThumbTraceEmulator<'b, SimpleSerial>>,
    ) -> Result<()> {
        emu.register_hook("init_uart", Self::hook_init_uart)?;
        emu.register_hook("getch", Self::hook_getch)?;
        Ok(())
    }

    pub fn hook_init_uart(emu: &mut Unicorn<ThumbTraceEmulator<SimpleSerial>>) -> bool {
        hook_force_return(emu);
        true
    }

    pub fn hook_getch(emu: &mut Unicorn<ThumbTraceEmulator<SimpleSerial>>) -> bool {
        while emu.get_data().victim_com.data.is_empty() {
            if !emu.process_inter_thread_communication() {
                return false;
            }
        }

        let char = emu.get_data_mut().victim_com.data.pop_front().unwrap();
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

impl Default for SimpleSerial {
    fn default() -> Self {
        Self::new()
    }
}
