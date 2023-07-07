// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use std::thread;

use capstone::Insn;
use capstone::InsnDetail;
use unicorn_engine::unicorn_const::Arch;
use unicorn_engine::unicorn_const::Mode;
use unicorn_engine::unicorn_const::Permission;
use unicorn_engine::Unicorn;

use crate::communication::*;
use crate::itc::create_itcs;
use crate::itc::RainbowITC;
use crate::leakage::*;
use crate::trace_emulator::*;
use crate::Command;

#[ctor::ctor]
fn init() {
    env_logger::init();
}

/// Communication stub. For testing.
pub struct NullCommunication {}

impl Communication for NullCommunication {}

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

fn new_emu_dummy<'a, L: LeakageModel>(
    leakage: L,
) -> (
    Unicorn<'a, ThumbTraceEmulator<'a, L, NullCommunication>>,
    RainbowITC,
) {
    let (to_emu, from_emu) = create_itcs();
    let mut emu =
        <Unicorn<'a, ThumbTraceEmulator<L, NullCommunication>> as ThumbTraceEmulatorTrait<
            L,
            NullCommunication,
        >>::new(Arch::ARM, Mode::LITTLE_ENDIAN, leakage, None, to_emu);
    emu.mem_map(0, 4096, Permission::EXEC).unwrap();
    emu.add_code_hook(
        0,
        4096,
        <Unicorn<'_, ThumbTraceEmulator<'_, L, NullCommunication>>>::hook_code,
    )
    .unwrap();
    (emu, from_emu)
}

/// Use dummy hook to check if it is executed
#[test]
fn test_hooks() {
    let (mut emu, _) = new_emu_dummy(NullLeakage::new());
    emu.get_data_mut().hooks.push((0, |emu| {
        emu.get_data_mut().tracing.capturing = true;
        false
    }));
    emu.emu_start(0, 4096, 0, 0).unwrap();
    assert!(emu.get_data().tracing.capturing)
}

/// Test communication with vicim by using a reflector
#[test]
fn test_victim_communication() {
    let (to_emu, from_emu) = create_itcs();
    thread::spawn(move || {
        let mut emu =
            <Unicorn<'_, ThumbTraceEmulator<NullLeakage, NullCommunication>> as ThumbTraceEmulatorTrait<
                NullLeakage,
                NullCommunication,
            >>::new(
                Arch::ARM,
                Mode::LITTLE_ENDIAN,
                NullLeakage::new(),
                None,
                from_emu
            );
        emu.mem_map(0, 4096, Permission::EXEC).unwrap();
        emu.add_code_hook(
            0,
            4096,
            <Unicorn<'_, ThumbTraceEmulator<'_, NullLeakage, NullCommunication>>>::hook_code,
        )
        .unwrap();
        emu.get_data_mut().hooks.push((0, |emu| {
            let inner = emu.get_data_mut();
            inner.itc.victim.send(inner.itc.victim.recv());
            false
        }));
        emu.emu_start(0, 4096, 0, 0).unwrap();
    });

    to_emu.victim.send(Command::VictimDataByte(0x00));
    assert_eq!(to_emu.victim.recv(), Command::VictimDataByte(0x00))
}

mod tests_leakage {
    use super::*;

    #[test]
    fn test_hamming_weight_leakage() {
        let (mut emu, _) = new_emu_dummy(HammingWeightLeakage::new());
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
