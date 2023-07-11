// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

//! Implementation of an Emulator generating (side-channel) traces for Thumb based binary code.

use capstone::arch::arm::ArmOperand;
use capstone::prelude::BuildsCapstone;
use capstone::prelude::DetailsArchInsn;
use capstone::Capstone;
use capstone::RegId;
use log::{info, trace};
use unicorn_engine::unicorn_const::{Arch, HookType, Mode, Permission};
use unicorn_engine::{RegisterARM, Unicorn};

use crate::asmutils::disassemble;
use crate::asmutils::ElfInfo;
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

pub const THUMB_TRACE_REGISTERS: [RegisterARM; 16] = [
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
    RegisterARM::PC,
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
    elfinfo: &'a ElfInfo<'a>,
    capstone: Capstone,
    hooks: Vec<(u64, Hook<L, C>)>,
    leakage: L,
    tracing: Tracing,
    pub(crate) victim_com: C,
    itc: BiChannel<ITCResponse, ITCRequest>,
}

pub struct Tracing {
    capturing: bool,
    register_values: Option<[u32; THUMB_TRACE_REGISTERS.len()]>,
    trace: Vec<f32>,
    instruction_trace: Vec<u32>,
}

impl Tracing {
    fn start_capturing(&mut self) {
        self.capturing = true;
        self.register_values = None;
        self.trace.clear();
        self.instruction_trace.clear();
    }

    fn stop_capturing(&mut self) {
        self.capturing = false;
    }
}

pub trait ThumbTraceEmulatorTrait<'a, L: LeakageModel, C: Communication> {
    type D;

    fn new(
        elfinfo: &'a ElfInfo<'a>,
        leakage: L,
        victim_com: C,
        itc: BiChannel<ITCResponse, ITCRequest>,
    ) -> Self;

    fn load(&mut self) -> Result<(), TraceEmulatorError>;

    fn start(&mut self);

    fn register_hook(&mut self, symbol: &str, hook: Hook<L, C>) -> Result<(), TraceEmulatorError>;

    fn hook_code(emu: &mut Unicorn<Self::D>, address: u64, size: u32);
}

impl<'a, L: LeakageModel, C: Communication> ThumbTraceEmulatorTrait<'a, L, C>
    for Unicorn<'a, ThumbTraceEmulator<'a, L, C>>
{
    type D = ThumbTraceEmulator<'a, L, C>;

    fn new(
        elfinfo: &'a ElfInfo<'a>,
        leakage: L,
        victim_com: C,
        itc: BiChannel<ITCResponse, ITCRequest>,
    ) -> Self {
        Unicorn::new_with_data(
            Arch::ARM,
            Mode::LITTLE_ENDIAN,
            ThumbTraceEmulator {
                elfinfo,
                capstone: Capstone::new()
                    .arm()
                    .mode(capstone::arch::arm::ArchMode::Thumb)
                    .detail(true)
                    .build()
                    .unwrap(),
                hooks: Vec::new(),
                leakage,
                tracing: Tracing {
                    register_values: None,
                    trace: Vec::new(),
                    instruction_trace: Vec::new(),
                    capturing: false,
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
    fn load(&mut self) -> Result<(), TraceEmulatorError> {
        let inner = self.get_data();
        for (i, (addr, program)) in inner.elfinfo.segments().enumerate() {
            self.mem_write(addr, program)?;
            if i == 0 {
                // Set initial register values
                let start_addr = u32::from_le_bytes(program[4..8].try_into().unwrap()) as u64;
                let initial_sp = u32::from_le_bytes(program[0..4].try_into().unwrap()) as u64;
                self.reg_write(RegisterARM::PC, start_addr)?;
                self.reg_write(RegisterARM::SP, initial_sp)?;
                info!("Initial registers: PC: {start_addr:08x} SP: {initial_sp:08x}");
                self.add_code_hook(addr, addr + program.len() as u64, Self::hook_code)?;
            }
        }

        Ok(())
    }

    /// Start emulation at current PC
    fn start(&mut self) {
        self.emu_start(self.pc_read().unwrap() | 1, 0, 0, 0)
            .unwrap();
    }

    /// Register a given `Hook` at the given symbol
    fn register_hook(&mut self, symbol: &str, hook: Hook<L, C>) -> Result<(), TraceEmulatorError> {
        let inner = self.get_data_mut();
        inner
            .hooks
            .push((*inner.elfinfo.symbol_map.get(symbol).unwrap(), hook));
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
        if inner.tracing.capturing {
            let regs_after = THUMB_TRACE_REGISTERS.map(|r| emu.reg_read(r).unwrap() as u32);
            if let Some(regs_before) = inner.tracing.register_values {
                let inner_mut = emu.get_data_mut();
                let address = regs_before[regs_before.len() - 1];
                let instruction = inner_mut
                    .elfinfo
                    .instruction_map
                    .get(&(address as u64))
                    .unwrap();

                inner_mut.tracing.trace.push(inner_mut.leakage.calculate(
                    instruction,
                    &inner_mut.capstone.insn_detail(instruction).unwrap(),
                    &regs_before,
                    &regs_after,
                ));
                inner_mut.tracing.instruction_trace.push(address);
            }
            emu.get_data_mut().tracing.register_values = Some(regs_after);
        }
    }
}

impl<'a, L: LeakageModel, C: Communication> ThumbTraceEmulator<'a, L, C> {
    /// Blocking function to process requests from main thread.
    /// Shall be called in an idle-loop of victim execution. E.g. `SimpleSerial::getch`.
    pub fn process_inter_thread_communication(&mut self) -> bool {
        match self.itc.recv() {
            Ok(ITCRequest::GetTrace(_)) => {
                self.itc
                    .send(ITCResponse::Trace(self.tracing.trace.clone()));
                true
            }
            Ok(ITCRequest::VictimData(data)) => {
                self.victim_com.write(data);
                true
            }
            Err(_) => false,
        }
    }
}

/// Implementation of ChipWhisperer™-Lite Arm (STM32F4)
pub fn new_simpleserialsocket_stm32f4<'a, L: LeakageModel>(
    elfinfo: &'a ElfInfo<'a>,
    leakage: L,
    itc: BiChannel<ITCResponse, ITCRequest>,
) -> Result<Unicorn<'a, ThumbTraceEmulator<'a, L, SimpleSerial>>, TraceEmulatorError> {
    let mut emu =
        <Unicorn<'a, ThumbTraceEmulator<'a, L, SimpleSerial>> as ThumbTraceEmulatorTrait<
            'a,
            L,
            SimpleSerial,
        >>::new(elfinfo, leakage, SimpleSerial::new(), itc);

    // Set memory map
    {
        emu.mem_map(0x0800_0000, 256 * 1024, Permission::READ | Permission::EXEC)
            .unwrap();
        emu.mem_map(0x2000_0000, 40 * 1024, Permission::READ | Permission::WRITE)
            .unwrap();
    }

    // Load content
    {
        emu.load().unwrap();
    }

    // Add hooks
    {
        emu.register_hook("platform_init", hook_force_return)
            .unwrap();
        emu.register_hook("trigger_setup", hook_force_return)
            .unwrap();
        emu.register_hook("trigger_high", hook_trigger_high)
            .unwrap();
        emu.register_hook("trigger_low", hook_trigger_low).unwrap();
        SimpleSerial::install_hooks(&mut emu).unwrap();
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
    emu.get_data_mut().tracing.start_capturing();

    true
}

/// Predefined hook that stops capturing a trace and sends the trace
pub fn hook_trigger_low<L: LeakageModel, C: Communication>(
    emu: &mut Unicorn<ThumbTraceEmulator<L, C>>,
) -> bool {
    hook_force_return(emu);
    emu.get_data_mut().tracing.stop_capturing();

    true
}

#[cfg(test)]
mod tests {
    use std::thread;

    use capstone::{Insn, InsnDetail};

    use crate::{itc::create_inter_thread_channels, leakage::HammingWeightLeakage};

    use super::*;

    #[ctor::ctor]
    fn init() {
        env_logger::init();
    }

    /// Communication stub. For testing.
    pub struct NullCommunication {}

    impl Communication for NullCommunication {
        fn write(&mut self, _data: Vec<u8>) {}
    }

    /// Null leakage. For testing
    pub struct NullLeakage {}

    impl NullLeakage {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl LeakageModel for NullLeakage {
        fn calculate(
            &self,
            _instruction: &Insn,
            _instruction_detail: &InsnDetail,
            _last_values: &[u32; THUMB_TRACE_REGISTERS.len()],
            _values: &[u32; THUMB_TRACE_REGISTERS.len()],
        ) -> f32 {
            0.0
        }
    }

    pub fn new_emu_dummy<'a, L: LeakageModel>(
        elfinfo: &'a ElfInfo<'a>,
        leakage: L,
    ) -> (
        Unicorn<'a, ThumbTraceEmulator<'a, L, NullCommunication>>,
        BiChannel<ITCRequest, ITCResponse>,
    ) {
        let (server, client) = create_inter_thread_channels();
        let mut emu =
        <Unicorn<'a, ThumbTraceEmulator<'a, L, NullCommunication>> as ThumbTraceEmulatorTrait<
            'a,
            L,
            NullCommunication,
        >>::new(elfinfo, leakage, NullCommunication {}, client);
        emu.mem_map(0, 4096, Permission::EXEC).unwrap();
        emu.add_code_hook(
            0,
            4096,
            <Unicorn<'_, ThumbTraceEmulator<'_, L, NullCommunication>>>::hook_code,
        )
        .unwrap();
        (emu, server)
    }

    /// Use dummy hook to check if it is executed
    #[test]
    fn test_hooks() {
        let elfinfo = ElfInfo::new(&[0x00, 0x00]);
        let (mut emu, _) = new_emu_dummy(&elfinfo, NullLeakage::new());
        emu.get_data_mut().hooks.push((0, |emu| {
            emu.get_data_mut().tracing.capturing = true;
            false
        }));
        emu.emu_start(0, 4096, 0, 0).unwrap();
        assert!(emu.get_data().tracing.capturing)
    }

    /// Test communication with victim by using a reflector
    #[test]
    fn test_victim_communication() {
        let (server, client) = create_inter_thread_channels();
        let elfinfo = ElfInfo::new(&[]);
        thread::spawn(move || {
            let mut emu =
            <Unicorn<ThumbTraceEmulator<NullLeakage, NullCommunication>> as ThumbTraceEmulatorTrait<
                NullLeakage,
                NullCommunication,
            >>::new(
                &elfinfo,
                NullLeakage {},
                NullCommunication {},
                client,
            );
            emu.mem_map(0, 4096, Permission::EXEC).unwrap();
            emu.add_code_hook(
                0,
                4096,
                <Unicorn<ThumbTraceEmulator<NullLeakage, NullCommunication>>>::hook_code,
            )
            .unwrap();
            emu.get_data_mut().hooks.push((0, |emu| {
                let inner = emu.get_data_mut();
                inner.itc.recv().unwrap();
                inner.itc.send(ITCResponse::Trace(vec![0.0]));
                false
            }));
            emu.emu_start(0, 4096, 0, 0).unwrap();
        });

        server.send(ITCRequest::GetTrace(0));
        assert_eq!(server.recv().unwrap(), ITCResponse::Trace(vec![0.0]));
    }

    #[test]
    fn test_hamming_weight_leakage() {
        let elfinfo = ElfInfo::new(&[0x00, 0x00]);
        let (mut emu, _) = new_emu_dummy(&elfinfo, HammingWeightLeakage::new());
        hook_trigger_high(&mut emu);
        emu.mem_write(
            0,
            &[
                0x00, 0x20, // movs r0, #0x00
                0x03, 0x20, // movs r0, #0x03
                0x07, 0x20, // movs r0, #0x07
                0x0F, 0x20, // movs r0, #0x0F
                0x00, 0xBF, // nop
            ],
        )
        .unwrap();
        emu.emu_start(1, u64::MAX, 0, 5).unwrap();

        assert_eq!(emu.get_data().tracing.trace, vec![0.0, 2.0, 3.0, 4.0])
    }
}
