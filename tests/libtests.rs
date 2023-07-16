// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use capstone::{Insn, InsnDetail};
use rainbow_rs::{
    asmutils::{ElfInfo, Segment},
    communication::Communication,
    itc::{create_inter_thread_channels, BiChannel, ITCRequest, ITCResponse},
    leakage::{HammingWeightLeakage, LeakageModel},
    ThumbTraceEmulator, ThumbTraceEmulatorTrait, THUMB_TRACE_REGISTERS,
};
use unicorn_engine::unicorn_const::Permission;

#[ctor::ctor]
fn init() {
    env_logger::init();
}

/// Communication stub. For testing.
pub struct Reflector {
    channel: BiChannel<ITCResponse, ITCRequest>,
}

impl Reflector {
    pub fn new(channel: BiChannel<ITCResponse, ITCRequest>) -> Self {
        Self { channel }
    }
}

impl Communication for Reflector {
    fn write(&mut self, data: Vec<u8>) {
        self.channel
            .send(ITCResponse::Trace(
                data.into_iter().map(|x| x as f32).collect(),
            ))
            .unwrap();
    }
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

#[test]
fn test_hamming_weight_leakage() {
    let (_, channel_emu) = create_inter_thread_channels();
    let elfinfo = ElfInfo::new_from_binary(vec![Segment(
        0x1000_0000,
        vec![
            0x00, 0xBF, // nop for hook
            0x00, 0x20, // movs r0, #0x00
            0x03, 0x20, // movs r0, #0x03
            0x07, 0x20, // movs r0, #0x07
            0x0F, 0x20, // movs r0, #0x0F
            0x00, 0xBF, // nop for hook
        ],
    )])
    .unwrap();
    let mut emu = ThumbTraceEmulator::new(
        &elfinfo,
        HammingWeightLeakage::new(),
        Reflector::new(channel_emu.clone()),
        channel_emu,
    )
    .unwrap();

    emu.mem_map(0x1000_0000, 1024, Permission::all()).unwrap();
    emu.load().unwrap();

    emu.register_hook_addr(0x1000_0000, |emu| {
        emu.start_capturing();
        true
    });
    emu.register_hook_addr(0x1000_000c, |emu| {
        emu.stop_capturing();
        false
    });

    emu.set_pc(0x1000_0001).unwrap();
    emu.start().unwrap();

    assert_eq!(emu.get_trace(), &vec![0.0, 2.0, 3.0, 4.0])
}

#[test]
fn test_victim_communication() {
    let (channel_host, channel_emu) = create_inter_thread_channels();
    let elfinfo = ElfInfo::new_from_binary(vec![Segment(
        0x1000_0000,
        vec![
            0x00, 0xBF, // nop for hook
            0x00, 0xBF, // nop for hook
            0x00, 0xBF, // nop for hook
            0x00, 0xBF, // nop for hook
        ],
    )])
    .unwrap();
    let mut emu = ThumbTraceEmulator::new(
        &elfinfo,
        HammingWeightLeakage::new(),
        Reflector::new(channel_emu.clone()),
        channel_emu,
    )
    .unwrap();

    emu.mem_map(0x1000_0000, 1024, Permission::all()).unwrap();
    emu.load().unwrap();

    emu.register_hook_addr(0x1000_0000, |emu| {
        emu.process_inter_thread_communication();
        false
    });

    channel_host
        .send(ITCRequest::VictimData(vec![1, 2, 3, 4]))
        .unwrap();

    emu.set_pc(0x1000_0001).unwrap();
    emu.start().unwrap();

    assert!(matches!(
        channel_host.recv().unwrap(),
        ITCResponse::Trace(v)
        if v == vec![1.0, 2.0, 3.0, 4.0]
    ))
}
