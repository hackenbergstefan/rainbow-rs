use std::error::Error;
use std::fmt;
use std::io::Read;

use super::asmutils::disassemble;
use super::communication::Communication;
use super::communication::SimpleSerial;
use capstone::prelude::BuildsCapstone;
use capstone::Capstone;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use log::info;
use unicorn_engine::unicorn_const::{uc_error, Arch, HookType, Mode, Permission};
use unicorn_engine::{RegisterARM, Unicorn};

#[derive(Debug)]
pub enum TraceEmulatorError {
    UcErr(uc_error),
    ElfParseError(elf::ParseError),
    IoError(std::io::Error),
    OtherError,
}

impl fmt::Display for TraceEmulatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<uc_error> for TraceEmulatorError {
    fn from(e: uc_error) -> Self {
        Self::UcErr(e)
    }
}
impl From<elf::ParseError> for TraceEmulatorError {
    fn from(e: elf::ParseError) -> Self {
        Self::ElfParseError(e)
    }
}

impl From<std::io::Error> for TraceEmulatorError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl Error for TraceEmulatorError {}

#[derive(Debug)]
pub struct MemoryInfo {
    pub symbols: Vec<(String, u64)>,
    pub start_address: u64,
}

use super::leakage::LeakageModel;

pub struct ThumbTraceEmulator<L: LeakageModel, C: Communication> {
    pub(crate) capstone: Capstone,
    pub(crate) capturing: bool,
    pub(crate) meminfo: MemoryInfo,
    pub(crate) hooks: Vec<(u64, fn(&mut Unicorn<'_, ThumbTraceEmulator<L, C>>))>,
    pub(crate) leakage: L,
    pub(crate) communication: C,
}

pub trait ThumbTraceEmulatorTrait<'a, L: LeakageModel, C: Communication> {
    fn new(
        arch: Arch,
        mode: Mode,
        leakage: L,
        communication: C,
    ) -> Unicorn<'a, ThumbTraceEmulator<L, C>>;

    fn load(&mut self, elffile: &str) -> Result<(), TraceEmulatorError>;

    fn register_hook(
        &mut self,
        symbol: &str,
        hook: fn(&mut Unicorn<'_, ThumbTraceEmulator<L, C>>),
    ) -> Result<(), TraceEmulatorError>;

    fn hook_code(emu: &mut Unicorn<'_, ThumbTraceEmulator<L, C>>, address: u64, size: u32);
}

impl<'a, L: LeakageModel, C: Communication> ThumbTraceEmulatorTrait<'a, L, C>
    for Unicorn<'a, ThumbTraceEmulator<L, C>>
{
    fn new(
        arch: Arch,
        mode: Mode,
        leakage: L,
        communication: C,
    ) -> Unicorn<'a, ThumbTraceEmulator<L, C>> {
        assert!(arch == Arch::ARM && mode == Mode::LITTLE_ENDIAN);

        Unicorn::new_with_data(
            arch,
            mode,
            ThumbTraceEmulator {
                capstone: Capstone::new()
                    .arm()
                    .mode(capstone::arch::arm::ArchMode::Thumb)
                    .detail(true)
                    .build()
                    .unwrap(),
                capturing: false,
                meminfo: MemoryInfo {
                    symbols: Vec::new(),
                    start_address: 0,
                },
                hooks: Vec::new(),
                leakage,
                communication,
            },
        )
        .unwrap()
    }

    fn load(&mut self, elffile: &str) -> Result<(), TraceEmulatorError> {
        let mut buf = Vec::new();
        std::fs::File::open(elffile)?.read_to_end(&mut buf)?;
        let elffile = ElfBytes::<'_, AnyEndian>::minimal_parse(buf.as_slice())?;

        {
            let data = self.get_data_mut();
            data.meminfo.symbols.clear();
            let (symtable, strtable) = elffile.symbol_table()?.unwrap();
            for symbol in symtable {
                data.meminfo.symbols.push((
                    strtable.get(symbol.st_name as usize)?.to_owned(),
                    symbol.st_value,
                ));
            }
        }

        for (i, header) in elffile
            .segments()
            .ok_or(TraceEmulatorError::OtherError)?
            .iter()
            .enumerate()
        {
            let program = elffile.segment_data(&header)?;
            self.mem_write(header.p_paddr, program)?;
            if i == 0 {
                // Set initial register values
                let start_addr = u32::from_le_bytes(program[4..8].try_into().unwrap()) as u64;
                let initial_sp = u32::from_le_bytes(program[0..4].try_into().unwrap()) as u64;
                self.reg_write(RegisterARM::PC, start_addr)?;
                self.reg_write(RegisterARM::SP, initial_sp)?;
                info!("Initial registers: PC: {start_addr:08x} SP: {initial_sp:08x}");
                self.add_code_hook(
                    header.p_paddr,
                    header.p_paddr + program.len() as u64,
                    Self::hook_code,
                )?;
                self.get_data_mut().meminfo.start_address = start_addr;
            }
        }

        Ok(())
    }

    fn register_hook(
        &mut self,
        symbol: &str,
        hook: fn(&mut Unicorn<'_, ThumbTraceEmulator<L, C>>),
    ) -> Result<(), TraceEmulatorError> {
        let data = self.get_data_mut();
        data.hooks.push((
            data.meminfo
                .symbols
                .iter()
                .find(|(sym, _addr)| sym == symbol)
                .ok_or(TraceEmulatorError::OtherError)?
                .1,
            hook,
        ));
        Ok(())
    }

    fn hook_code(emu: &mut Unicorn<'_, ThumbTraceEmulator<L, C>>, address: u64, size: u32) {
        let data = emu.get_data();

        // Execute hook if present
        for (hook_addr, hook_func) in &data.hooks {
            if address == hook_addr & !1 {
                info!("Execute hook at {:08x}", address);
                hook_func(emu);
                return;
            }
        }

        // Log current instruction
        if log::log_enabled!(log::Level::Info) {
            let instruction = disassemble(emu, &data.capstone, address, size as usize);
            info!(
                "Executing {:08x}: {:} {:}",
                instruction.address(),
                instruction.mnemonic().unwrap(),
                instruction.op_str().unwrap()
            );
        }

        // Add tracepoint
        if data.capturing {
            // Self::capture_instruction(emu, address, size as usize);
        }
    }
}

pub fn new_simpleserialsocket_stm32f4<'a, L: LeakageModel>(
    elffile: &str,
    leakage: L,
    socket_address: &str,
) -> Result<Unicorn<'a, ThumbTraceEmulator<L, SimpleSerial>>, TraceEmulatorError> {
    let mut emu = <Unicorn<'a, ThumbTraceEmulator<L, SimpleSerial>> as ThumbTraceEmulatorTrait<
        'a,
        L,
        SimpleSerial,
    >>::new(
        Arch::ARM,
        Mode::LITTLE_ENDIAN,
        leakage,
        SimpleSerial::new(socket_address)?,
    );
    // Set memory map
    {
        emu.mem_map(0x0800_0000, 256 * 1024, Permission::READ | Permission::EXEC)?;
        emu.mem_map(0x2000_0000, 40 * 1024, Permission::READ | Permission::WRITE)?;
    }

    // Load content
    {
        emu.load(elffile)?;
    }

    // Add hooks
    {
        emu.register_hook("platform_init", hook_force_return)?;
        emu.register_hook("trigger_setup", hook_force_return)?;
        emu.register_hook("init_uart", SimpleSerial::hook_init_uart)?;
        emu.register_hook("getch", SimpleSerial::hook_getch)?;
        emu.register_hook("trigger_high", function_trigger_high)?;
        emu.register_hook("trigger_low", function_trigger_low)?;
    }
    emu.add_mem_hook(
        HookType::MEM_ALL,
        0,
        0xFFFF_0000,
        |_emu, memtype, address, _, _| {
            println!("{:?} at {:08x}", memtype, address);
            true
        },
    )
    .unwrap();

    for (addr, _func) in &emu.get_data().hooks {
        println!("Hook at {:08x}", addr);
    }

    Ok(emu)
}

// -----------------------------------------------------------------------------------------------

pub fn hook_force_return<L: LeakageModel, C: Communication>(
    emu: &mut Unicorn<'_, ThumbTraceEmulator<L, C>>,
) {
    let lr = emu.reg_read(RegisterARM::LR).unwrap();
    emu.set_pc(lr).unwrap();
}

pub fn function_trigger_high<L: LeakageModel, C: Communication>(
    emu: &mut Unicorn<'_, ThumbTraceEmulator<L, C>>,
) {
    emu.get_data_mut().capturing = true;
    hook_force_return(emu);
}

pub fn function_trigger_low<L: LeakageModel, C: Communication>(
    emu: &mut Unicorn<'_, ThumbTraceEmulator<L, C>>,
) {
    emu.get_data_mut().capturing = false;
    hook_force_return(emu);
}
