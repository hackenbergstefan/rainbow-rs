// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

//! Implementation of facilities communicating with `ThumbTraceEmulator`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use log::info;
use unicorn_engine::{RegisterARM, Unicorn};

use crate::error::TraceEmulatorError;
use crate::trace_emulator::hook_force_return;
use crate::trace_emulator::ThumbTraceEmulator;

pub trait Communication {
    fn read(&mut self, size: usize) -> Result<Vec<u8>, TraceEmulatorError>;
    fn write(&mut self, data: &[u8]) -> Result<(), TraceEmulatorError>;
    fn write_trace(&mut self, trace: &[u8]) -> Result<(), TraceEmulatorError>;
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
    stream: TcpStream,
}

impl SimpleSerial {
    pub fn new(socket_address: &str) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(socket_address)?;
        let (stream, _) = listener.accept()?;
        Ok(Self { stream })
    }

    pub fn hook_init_uart<'a>(emu: &mut Unicorn<'a, ThumbTraceEmulator<SimpleSerial>>) -> bool {
        hook_force_return(emu);
        true
    }

    pub fn hook_getch<'a>(emu: &mut Unicorn<'a, ThumbTraceEmulator<SimpleSerial>>) -> bool {
        match emu.get_data_mut().communication.read(1) {
            Ok(val) => {
                emu.reg_write(RegisterARM::R0, val[0] as u64).unwrap();
                hook_force_return(emu);
                true
            }
            Err(_) => false,
        }
    }
}

impl Communication for SimpleSerial {
    fn read(&mut self, size: usize) -> Result<Vec<u8>, TraceEmulatorError> {
        let mut data = vec![0; size];
        self.stream.read_exact(data.as_mut_slice())?;
        info!("SimpleSerial::read {data:?}");
        Ok(data)
    }

    fn write(&mut self, data: &[u8]) -> Result<(), TraceEmulatorError> {
        self.stream.write_all(data)?;
        Ok(())
    }

    fn write_trace(&mut self, data: &[u8]) -> Result<(), TraceEmulatorError> {
        // dbg!(data.len());
        self.stream.write_all(data)?;
        Ok(())
    }
}
