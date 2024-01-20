// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

//! Implementation of an Emulator generating (side-channel) traces for Thumb based binary code.
//!
pub mod asmutils;
pub mod communication;
pub mod error;
pub mod itc;
pub mod leakage;

use anyhow::{Context, Result};
use arrayvec::ArrayVec;
use capstone::{
    arch::arm::ArmOperand,
    prelude::{BuildsCapstone, DetailsArchInsn},
    Capstone, OwnedInsn,
};
use log::{info, trace};
use unicorn_engine::{
    unicorn_const::{Arch, HookType, MemType, Mode, Permission},
    RegisterARM, Unicorn,
};

use asmutils::{ElfInfo, Segment, SideChannelOperandsValues};
use communication::{Communication, SimpleSerial};
use error::{CapstoneError, UcError};
use itc::{BiChannel, ITCRequest, ITCResponse};
use leakage::LeakageModel;

type Hook<L, C> = fn(&mut Unicorn<ThumbTraceEmulator<L, C>>) -> bool;

pub struct ThumbTraceEmulator<'a, L: LeakageModel, C: Communication> {
    elfinfo: &'a ElfInfo,
    capstone: Capstone,
    hooks: Vec<(u64, Hook<L, C>)>,
    leakage: L,
    tracing: Tracing<'a>,
    victim_com: C,
    itc: BiChannel<ITCResponse, ITCRequest>,
}

pub struct ScaData<'a> {
    instruction: &'a OwnedInsn<'static>,
    registers: &'a Vec<ArmOperand>,
    regvalues_before: ArrayVec<u64, 8>,
    regvalues_after: ArrayVec<u64, 8>,
}

pub struct Tracing<'a> {
    capturing: bool,
    register_values: ArrayVec<ScaData<'a>, 16>,
    trace: Vec<f32>,
    instruction_trace: Vec<u32>,
    temporary_memory_leakage: ArrayVec<f32, 16>,
}

impl<'a> Tracing<'a> {
    fn start_capturing(&mut self) {
        self.capturing = true;
        self.register_values.clear();
        self.trace.clear();
        self.instruction_trace.clear();
    }

    fn stop_capturing(&mut self) {
        self.capturing = false;
    }
}

pub trait ThumbTraceEmulatorTrait<'a, L: LeakageModel, C: Communication>: Sized {
    fn new(
        elfinfo: &'a ElfInfo,
        leakage: L,
        victim_com: C,
        itc: BiChannel<ITCResponse, ITCRequest>,
    ) -> Result<Self>;

    fn load(&mut self) -> Result<()>;

    fn start(&mut self) -> Result<()>;

    fn register_hook(&mut self, symbol: &str, hook: Hook<L, C>) -> Result<()>;

    fn register_hook_addr(&mut self, address: u64, hook: Hook<L, C>);

    fn hook_code(&mut self, address: u64, size: u32);

    fn hook_memory(&mut self, _memtype: MemType, address: u64, size: usize, newvalue: i64) -> bool;

    fn start_capturing(&mut self);

    fn stop_capturing(&mut self);

    fn get_trace(&self) -> &Vec<f32>;

    fn process_inter_thread_communication(&mut self) -> bool;
}

impl<'a, L: LeakageModel, C: Communication> ThumbTraceEmulatorTrait<'a, L, C>
    for Unicorn<'_, ThumbTraceEmulator<'a, L, C>>
{
    fn new(
        elfinfo: &'a ElfInfo,
        leakage: L,
        victim_com: C,
        itc: BiChannel<ITCResponse, ITCRequest>,
    ) -> Result<Self> {
        Ok(Unicorn::new_with_data(
            Arch::ARM,
            Mode::LITTLE_ENDIAN,
            ThumbTraceEmulator {
                elfinfo,
                capstone: Capstone::new()
                    .arm()
                    .mode(capstone::arch::arm::ArchMode::Thumb)
                    .detail(true)
                    .build()
                    .map_err(CapstoneError::new)?,
                hooks: Vec::new(),
                leakage,
                tracing: Tracing {
                    register_values: ArrayVec::new(),
                    trace: Vec::new(),
                    instruction_trace: Vec::new(),
                    capturing: false,
                    temporary_memory_leakage: ArrayVec::new(),
                },
                victim_com,
                itc,
            },
        )
        .map_err(UcError::new)?)
    }

    /// Load given elffile into Emulator.
    ///
    /// Memory must already be mapped.
    /// It is assumed that the very first segment starts with the reset vector.
    fn load(&mut self) -> Result<()> {
        for (i, Segment(addr, program)) in self.get_data().elfinfo.segments().enumerate() {
            let addr = *addr;
            self.mem_write(addr, program).map_err(UcError::new)?;
            info!("Load {:08x} - {:08x} ", addr, addr + program.len() as u64);
            if i == 0 {
                // Set initial register values
                let start_addr = u32::from_le_bytes(program[4..8].try_into()?) as u64;
                let initial_sp = u32::from_le_bytes(program[0..4].try_into()?) as u64;
                self.reg_write(RegisterARM::PC, start_addr)
                    .map_err(UcError::new)?;
                self.reg_write(RegisterARM::SP, initial_sp)
                    .map_err(UcError::new)?;
                info!("Initial registers: PC: {start_addr:08x} SP: {initial_sp:08x}");
                self.add_code_hook(addr, addr + program.len() as u64, |emu, address, size| {
                    emu.hook_code(address, size);
                })
                .map_err(UcError::new)?;
            }
        }
        self.add_mem_hook(
            HookType::MEM_WRITE,
            0,
            0xFFFF_0000,
            |emu, memtype, address, size, newvalue| -> bool {
                emu.hook_memory(memtype, address, size, newvalue)
            },
        )
        .unwrap();

        Ok(())
    }

    /// Start emulation at current PC
    fn start(&mut self) -> Result<()> {
        self.emu_start(self.pc_read().map_err(UcError::new)? | 1, 0, 0, 0)
            .map_err(UcError::new)?;
        Ok(())
    }

    /// Register a given `Hook` at the given symbol
    fn register_hook(&mut self, symbol: &str, hook: Hook<L, C>) -> Result<()> {
        let address = self
            .get_data()
            .elfinfo
            .get_symbol(symbol)
            .context("Not found")?;
        self.register_hook_addr(address, hook);
        Ok(())
    }

    /// Register a given `Hook` at a given `address`
    fn register_hook_addr(&mut self, address: u64, hook: Hook<L, C>) {
        self.get_data_mut().hooks.push((address, hook));
    }

    /// Generic hook that is executed for _every_ instruction
    fn hook_code(&mut self, address: u64, _size: u32) {
        let inner = self.get_data();

        // Execute hook if present
        for (hook_addr, hook_func) in &inner.hooks {
            if address == hook_addr & !1 {
                info!("Execute hook at {:08x}", address);
                if !hook_func(self) {
                    self.emu_stop().unwrap();
                }
                return;
            }
        }

        // Log current instruction
        if log::log_enabled!(log::Level::Info) {
            let (instruction, _) = inner.elfinfo.get_instruction(&address).unwrap();
            info!(
                "Executing {:08x}: {:} {:} [{:?}] operands: {:?}\n\t read: {:?} write: {:?} ({:?})",
                instruction.address(),
                instruction.mnemonic().unwrap(),
                instruction.op_str().unwrap(),
                instruction.id(),
                inner
                    .capstone
                    .insn_detail(instruction)
                    .unwrap()
                    .arch_detail()
                    .arm()
                    .unwrap()
                    .operands()
                    .collect::<Vec<ArmOperand>>(),
                inner.capstone.insn_detail(instruction).unwrap().regs_read(),
                inner
                    .capstone
                    .insn_detail(instruction)
                    .unwrap()
                    .regs_write(),
                inner
                    .capstone
                    .insn_detail(instruction)
                    .unwrap()
                    .groups()
                    .iter()
                    .map(|g| inner.capstone.group_name(*g).unwrap())
                    .collect::<String>()
            );
        }

        // Add tracepoint if capturing
        if inner.tracing.capturing {
            // Extend last ScaData by updated register values
            if let Some(scadata) = inner.tracing.register_values.last() {
                self.get_data_mut()
                    .tracing
                    .register_values
                    .last_mut()
                    .unwrap()
                    .regvalues_after = scadata.registers.sca_operands_values(self);
            }

            // Calculate leakage if ready
            let inner = self.get_data();
            if inner.tracing.register_values.len() == inner.leakage.cycles_for_calc() {
                let inner_mut = self.get_data_mut();
                let leakage = inner_mut
                    .leakage
                    .calculate(inner_mut.tracing.register_values.as_slice());
                inner_mut.tracing.trace.push(leakage);
                inner_mut.tracing.instruction_trace.push(address as u32);
                inner_mut.tracing.register_values.clear();

                // Append cached memory leakages
                for &mem_leakage in &inner_mut.tracing.temporary_memory_leakage {
                    inner_mut.tracing.trace.push(mem_leakage);
                    inner_mut.tracing.instruction_trace.push(address as u32);
                }
                inner_mut.tracing.temporary_memory_leakage.clear();
            }

            // Append to sidechannel data
            {
                let (instruction, instruction_registers) =
                    self.get_data().elfinfo.get_instruction(&address).unwrap();
                let regvalues_before = instruction_registers.sca_operands_values(self);
                self.get_data_mut().tracing.register_values.push(ScaData {
                    instruction,
                    registers: instruction_registers,
                    regvalues_before,
                    regvalues_after: ArrayVec::new(),
                });
            }
        }
    }

    fn hook_memory(&mut self, _memtype: MemType, address: u64, size: usize, newvalue: i64) -> bool {
        if self.get_data().tracing.capturing {
            let oldvalue = {
                let mut oldvalue = [0; 8];
                self.mem_read(address, &mut oldvalue[..size]).unwrap();
                u64::from_le_bytes(oldvalue)
            };
            info!("hook_memory {address:08x} {size} {oldvalue:08x} -> {newvalue:08x}");

            let inner_mut = self.get_data_mut();
            inner_mut.tracing.temporary_memory_leakage.push(
                inner_mut
                    .leakage
                    .calculate_memory(oldvalue, newvalue as u64),
            );
        }
        true
    }

    fn start_capturing(&mut self) {
        self.get_data_mut().tracing.start_capturing();
    }

    fn stop_capturing(&mut self) {
        self.get_data_mut().tracing.stop_capturing();
    }

    fn get_trace(&self) -> &Vec<f32> {
        &self.get_data().tracing.trace
    }

    /// Blocking function to process requests from main thread.
    /// Shall be called in an idle-loop of victim execution. E.g. `SimpleSerial::getch`.
    fn process_inter_thread_communication(&mut self) -> bool {
        let inner = self.get_data_mut();
        match inner.itc.recv() {
            Ok(ITCRequest::VictimData(data)) => {
                inner.victim_com.write(data);
                true
            }
            Ok(ITCRequest::Terminate) => false,
            Err(_) => false,
        }
    }
}

impl<'a, L: LeakageModel, C: Communication> ThumbTraceEmulator<'a, L, C> {
    pub fn new(
        elfinfo: &'a ElfInfo,
        leakage: L,
        victim_com: C,
        itc: BiChannel<ITCResponse, ITCRequest>,
    ) -> Result<Unicorn<'_, ThumbTraceEmulator<'_, L, C>>> {
        <Unicorn<'a, ThumbTraceEmulator<'a, L, C>> as ThumbTraceEmulatorTrait<'a, L, C>>::new(
            elfinfo, leakage, victim_com, itc,
        )
    }
}

/// Implementation of ChipWhisperer™-Lite Arm (STM32F4)
pub fn new_simpleserialsocket_stm32f4<'a, L: LeakageModel>(
    elfinfo: &'a ElfInfo,
    leakage: L,
    itc: BiChannel<ITCResponse, ITCRequest>,
) -> Result<Unicorn<'a, ThumbTraceEmulator<'a, L, SimpleSerial>>> {
    let mut emu =
        <Unicorn<'a, ThumbTraceEmulator<'a, L, SimpleSerial>> as ThumbTraceEmulatorTrait<
            'a,
            L,
            SimpleSerial,
        >>::new(elfinfo, leakage, SimpleSerial::new(), itc)?;

    // Set memory map
    {
        emu.mem_map(0x0800_0000, 256 * 1024, Permission::READ | Permission::EXEC)
            .map_err(UcError::new)?;
        emu.mem_map(0x2000_0000, 40 * 1024, Permission::READ | Permission::WRITE)
            .map_err(UcError::new)?;
    }

    // Load content
    {
        emu.load()?;
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
        .map_err(UcError::new)?;
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
    emu.get_data_mut().tracing.start_capturing();

    true
}

/// Predefined hook that stops capturing a trace and sends the trace
pub fn hook_trigger_low<L: LeakageModel, C: Communication>(
    emu: &mut Unicorn<ThumbTraceEmulator<L, C>>,
) -> bool {
    hook_force_return(emu);
    let inner = emu.get_data_mut();
    inner.tracing.stop_capturing();
    inner
        .itc
        .send(ITCResponse::Trace(inner.tracing.trace.clone()))
        .unwrap();

    true
}
