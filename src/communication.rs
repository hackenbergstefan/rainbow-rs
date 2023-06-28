use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use log::info;
use unicorn_engine::{RegisterARM, Unicorn};

use super::error::TraceEmulatorError;
use super::leakage::LeakageModel;
use super::trace_emulator::hook_force_return;
use super::trace_emulator::ThumbTraceEmulator;

pub trait Communication {
    fn read(&mut self, size: usize) -> Result<Vec<u8>, TraceEmulatorError>;
    fn write(&mut self, data: &[u8]) -> Result<(), TraceEmulatorError>;
}

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

    pub fn hook_init_uart<'a, L: LeakageModel>(
        emu: &mut Unicorn<'a, ThumbTraceEmulator<L, SimpleSerial>>,
    ) -> bool {
        hook_force_return(emu);
        true
    }

    pub fn hook_getch<'a, L: LeakageModel>(
        emu: &mut Unicorn<'a, ThumbTraceEmulator<L, SimpleSerial>>,
    ) -> bool {
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
}
