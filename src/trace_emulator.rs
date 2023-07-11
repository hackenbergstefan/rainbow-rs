// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

//! Implementation of an Emulator generating (side-channel) traces for Thumb based binary code.

use std::io::Read;

use capstone::arch::arm::ArmOperand;
use capstone::prelude::BuildsCapstone;
use capstone::prelude::DetailsArchInsn;
use capstone::Capstone;
use capstone::OwnedInsn;
use capstone::RegId;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use log::{info, trace};
use unicorn_engine::unicorn_const::{Arch, HookType, Mode, Permission};
use unicorn_engine::{RegisterARM, Unicorn};

use crate::asmutils::disassemble;
use crate::communication::Communication;
use crate::communication::SimpleSerial;
use crate::error::TraceEmulatorError;
use crate::itc::BiChannel;
use crate::itc::ITCRequest;
use crate::itc::ITCResponse;
use crate::leakage::LeakageModel;

#[derive(Debug)]
pub struct MemoryInfo {
    pub symbols: Vec<(String, u64)>,
    pub start_address: u64,
}

pub const THUMB_TRACE_REGISTERS: [RegisterARM; 15] = [
    RegisterARM::R0,
    RegisterARM::R1,
    RegisterARM::R2,
    RegisterARM::R3,
    RegisterARM::R4,
    RegisterARM::R5,
    RegisterARM::R6,
    RegisterARM::R7,
    RegisterARM::R8,
    RegisterARM::R9,
    RegisterARM::R10,
    RegisterARM::R11,
    RegisterARM::R12,
    RegisterARM::LR,
    RegisterARM::XPSR,
    // RegisterARM::PC,
    // RegisterARM::SP,
];

pub fn regid2regindex(regid: RegId) -> Option<(usize, RegisterARM)> {
    for (i, reg) in THUMB_TRACE_REGISTERS.iter().enumerate() {
        if regid.0 == *reg as u16 {
            return Some((i, *reg));
        }
    }
    None
}

type Hook<L, C> = fn(&mut Unicorn<ThumbTraceEmulator<L, C>>) -> bool;

pub struct ThumbTraceEmulator<'a, L: LeakageModel, C: Communication> {
    pub(crate) capstone: Capstone,
    pub(crate) meminfo: MemoryInfo,
    pub(crate) hooks: Vec<(u64, Hook<L, C>)>,
    pub(crate) leakage: L,
    pub(crate) tracing: Tracing<'a>,
    pub(crate) victim_com: C,
    pub(crate) itc: BiChannel<ITCResponse, ITCRequest>,
}

pub struct Tracing<'a> {
    pub(crate) capturing: bool,
    pub(crate) last_register_values: [u32; THUMB_TRACE_REGISTERS.len()],
    pub(crate) instruction: Option<OwnedInsn<'a>>,
    pub(crate) trace: Vec<f32>,
    pub(crate) instruction_trace: Vec<OwnedInsn<'a>>,
    pub(crate) max_samples: Option<u32>,
}

pub trait ThumbTraceEmulatorTrait<L: LeakageModel, C: Communication> {
    type D;

    fn new(
        arch: Arch,
        mode: Mode,
        leakage: L,
        victim_com: C,
        max_samples: Option<u32>,
        itc: BiChannel<ITCResponse, ITCRequest>,
    ) -> Self;

    fn load(&mut self, elffile: &str) -> Result<(), TraceEmulatorError>;

    fn register_hook(&mut self, symbol: &str, hook: Hook<L, C>) -> Result<(), TraceEmulatorError>;

    fn hook_code(emu: &mut Unicorn<Self::D>, address: u64, size: u32);
}

impl<'a, L: LeakageModel, C: Communication> ThumbTraceEmulatorTrait<L, C>
    for Unicorn<'a, ThumbTraceEmulator<'a, L, C>>
{
    type D = ThumbTraceEmulator<'a, L, C>;

    fn new(
        arch: Arch,
        mode: Mode,
        leakage: L,
        victim_com: C,
        max_samples: Option<u32>,
        itc: BiChannel<ITCResponse, ITCRequest>,
    ) -> Self {
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
                meminfo: MemoryInfo {
                    symbols: Vec::new(),
                    start_address: 0,
                },
                hooks: Vec::new(),
                leakage,
                tracing: Tracing {
                    last_register_values: [0; THUMB_TRACE_REGISTERS.len()],
                    trace: Vec::new(),
                    instruction_trace: Vec::new(),
                    instruction: None,
                    capturing: false,
                    max_samples,
                },
                victim_com,
                itc,
            },
        )
        .unwrap()
    }

    /// Load given elffile into Emulator.
    ///
    /// Memory must already be mapped.
    /// It is assumed that the very first segment starts with the reset vector.
    fn load(&mut self, elffile: &str) -> Result<(), TraceEmulatorError> {
        let mut buf = Vec::new();
        std::fs::File::open(elffile)?.read_to_end(&mut buf)?;
        let elffile = ElfBytes::<'_, AnyEndian>::minimal_parse(buf.as_slice())?;

        {
            let inner = self.get_data_mut();
            inner.meminfo.symbols.clear();
            let (symtable, strtable) = elffile.symbol_table()?.unwrap();
            for symbol in symtable {
                inner.meminfo.symbols.push((
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

    /// Register a given `Hook` at the given symbol
    fn register_hook(&mut self, symbol: &str, hook: Hook<L, C>) -> Result<(), TraceEmulatorError> {
        let inner = self.get_data_mut();
        inner.hooks.push((
            inner
                .meminfo
                .symbols
                .iter()
                .find(|(sym, _addr)| sym == symbol)
                .ok_or(TraceEmulatorError::OtherError)?
                .1,
            hook,
        ));
        Ok(())
    }

    /// Generic hook that is executed for _every_ instruction
    fn hook_code(emu: &mut Unicorn<ThumbTraceEmulator<L, C>>, address: u64, size: u32) {
        let inner = emu.get_data();

        // Execute hook if present
        for (hook_addr, hook_func) in &inner.hooks {
            if address == hook_addr & !1 {
                info!("Execute hook at {:08x}", address);
                if !hook_func(emu) {
                    emu.emu_stop().unwrap();
                }
                return;
            }
        }

        // Log current instruction
        if log::log_enabled!(log::Level::Info) {
            let instruction = disassemble(emu, &inner.capstone, address, size as usize);
            let detail = inner.capstone.insn_detail(&instruction).unwrap();
            info!(
                "Executing {:08x}: {:} {:} operands: {:?}",
                instruction.address(),
                instruction.mnemonic().unwrap(),
                instruction.op_str().unwrap(),
                detail
                    .arch_detail()
                    .arm()
                    .unwrap()
                    .operands()
                    .collect::<Vec<ArmOperand>>()
            );
        }

        // Add tracepoint if capturing
        if inner.tracing.capturing
            && (inner.tracing.max_samples.is_none()
                || inner.tracing.max_samples.unwrap() as usize > inner.tracing.trace.len())
        {
            // During this hook the instruction is not executed yet.
            // So, the corresponding register values will be updated in the next call
            // - `instruction` and `last_register_values` belong together and refer to the already executed instruction
            // - `next_instruction`, `register_values` belong together

            let register_values = THUMB_TRACE_REGISTERS.map(|r| emu.reg_read(r).unwrap() as u32);
            let next_instruction = disassemble(emu, &inner.capstone, address, size as usize);

            let inner_mut = emu.get_data_mut();
            if let Some(instruction) = inner_mut.tracing.instruction.as_deref() {
                inner_mut
                    .tracing
                    .instruction_trace
                    .push(OwnedInsn::from(instruction));
                inner_mut.tracing.trace.push(inner_mut.leakage.calculate(
                    instruction,
                    &inner_mut.capstone.insn_detail(instruction).unwrap(),
                    &inner_mut.tracing.last_register_values,
                    &register_values,
                ));
            }
            inner_mut.tracing.last_register_values = register_values;
            inner_mut.tracing.instruction = Some(next_instruction);
        }
    }
}

impl<'a, L: LeakageModel, C: Communication> ThumbTraceEmulator<'a, L, C> {
    /// Blocking function to process requests from main thread.
    /// Shall be called in an idle-loop of victim execution. E.g. `SimpleSerial::getch`.
    pub fn process_inter_thread_communication(&mut self) -> bool {
        match self.itc.recv() {
            Ok(ITCRequest::GetTrace(_)) => {
                // println!("Send GetTrace");
                self.itc
                    .send(ITCResponse::Trace(self.tracing.trace.clone()));
                true
            }
            Ok(ITCRequest::VictimData(data)) => {
                // println!("Send VictimData");
                self.victim_com.write(data);
                true
            }
            Err(_) => false,
        }
    }
}

/// Implementation of ChipWhisperer™-Lite Arm (STM32F4)
pub fn new_simpleserialsocket_stm32f4<'a, L: LeakageModel>(
    elffile: &str,
    leakage: L,
    max_samples: Option<u32>,
    itc: BiChannel<ITCResponse, ITCRequest>,
) -> Result<Unicorn<'a, ThumbTraceEmulator<'a, L, SimpleSerial>>, TraceEmulatorError> {
    let mut emu =
        <Unicorn<'a, ThumbTraceEmulator<'a, L, SimpleSerial>> as ThumbTraceEmulatorTrait<
            L,
            SimpleSerial,
        >>::new(
            Arch::ARM,
            Mode::LITTLE_ENDIAN,
            leakage,
            SimpleSerial::new(),
            max_samples,
            itc,
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
        emu.register_hook("trigger_high", hook_trigger_high)?;
        emu.register_hook("trigger_low", hook_trigger_low)?;
        SimpleSerial::install_hooks(&mut emu)?;
    }

    if log::log_enabled!(log::Level::Trace) {
        emu.add_mem_hook(
            HookType::MEM_ALL,
            0,
            0xFFFF_0000,
            |_emu, memtype, address, _, _| {
                trace!("{:?} at {:08x}", memtype, address);
                true
            },
        )
        .unwrap();
    }

    Ok(emu)
}

// -----------------------------------------------------------------------------------------------

/// Predefined hook that just returns from the current function by setting PC := LR
pub fn hook_force_return<L: LeakageModel, C: Communication>(
    emu: &mut Unicorn<ThumbTraceEmulator<L, C>>,
) -> bool {
    let lr = emu.reg_read(RegisterARM::LR).unwrap();
    emu.set_pc(lr).unwrap();

    true
}

/// Predefined hook that start capturing a trace
pub fn hook_trigger_high<L: LeakageModel, C: Communication>(
    emu: &mut Unicorn<ThumbTraceEmulator<L, C>>,
) -> bool {
    hook_force_return(emu);

    let inner = emu.get_data_mut();
    inner.tracing.capturing = true;
    inner.tracing.trace.clear();
    inner.tracing.instruction = None;

    true
}

/// Predefined hook that stops capturing a trace and sends the trace
pub fn hook_trigger_low<L: LeakageModel, C: Communication>(
    emu: &mut Unicorn<ThumbTraceEmulator<L, C>>,
) -> bool {
    hook_force_return(emu);
    emu.get_data_mut().tracing.capturing = false;

    true
}
