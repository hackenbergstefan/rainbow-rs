// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use arrayvec::ArrayVec;
use rainbow_rs::{
    asmutils::{ElfInfo, Segment},
    communication::Communication,
    itc::{create_inter_thread_channels, BiChannel, ITCRequest, ITCResponse},
    leakage::{HammingDistanceLeakage, HammingWeightLeakage, Leakage, LeakageModel},
    ScaData, ThumbTraceEmulator, ThumbTraceEmulatorTrait,
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
                0,
                data.into_iter().map(|x| x as f32).collect(),
            ))
            .unwrap();
    }
}

/// Null leakage. For testing
pub struct NullLeakage {}

impl Default for NullLeakage {
    fn default() -> Self {
        Self::new()
    }
}

impl NullLeakage {
    pub fn new() -> Self {
        Self {}
    }
}

impl LeakageModel for NullLeakage {
    fn calculate<'a>(&mut self, scadata: &[ScaData<'a>]) -> Leakage<'a> {
        Leakage {
            instruction: scadata[0].instruction,
            values: ArrayVec::new(),
        }
    }

    fn cycles_for_calc(&self) -> usize {
        1
    }

    #[inline]
    fn memory_buswidth(&self) -> usize {
        4
    }
}

fn generate_leakage(leakage: Box<dyn LeakageModel>, segment: Segment) -> Vec<f32> {
    let (_, channel_emu) = create_inter_thread_channels();
    let elfinfo = ElfInfo::new_from_binary(vec![segment]).unwrap();
    let mut emu = ThumbTraceEmulator::new(
        &elfinfo,
        leakage,
        Reflector::new(channel_emu.clone()),
        channel_emu,
    )
    .unwrap();

    emu.mem_map(
        elfinfo.segments().next().unwrap().start(),
        1024,
        Permission::all(),
    )
    .unwrap();
    emu.load().unwrap();

    emu.register_hook_addr(elfinfo.segments().next().unwrap().start(), |emu| {
        emu.start_capturing();
        true
    });
    emu.register_hook_addr(elfinfo.segments().next().unwrap().end() - 1, |emu| {
        emu.stop_capturing();
        false
    });

    emu.set_pc(elfinfo.segments().next().unwrap().start() + 1)
        .unwrap();
    emu.start().unwrap();

    emu.get_trace().clone()
}

#[test]
fn test_hamming_weight_leakage() {
    // Test basic hamming weight changes
    assert_eq!(
        &generate_leakage(
            Box::new(HammingWeightLeakage::new()),
            Segment(
                0x1000_0000,
                vec![
                    0x00, 0xBF, // nop for hook
                    0x00, 0x20, // movs r0, #0x00
                    0x03, 0x20, // movs r0, #0x03
                    0x07, 0x20, // movs r0, #0x07
                    0x0F, 0x20, // movs r0, #0x0F
                    0x00, 0xBF, // nop
                    0x00, 0xBF, // nop for hook
                ],
            )
        ),
        &vec![0.0, 2.0, 3.0, 4.0]
    );
}

#[test]
fn test_hamming_weight_leakage_memory() {
    assert_eq!(
        &generate_leakage(
            Box::new(HammingWeightLeakage::new()),
            Segment(
                0x1000_0000,
                vec![
                    0x00, 0xBF, // nop for hook
                    0x5f, 0xf4, 0x80, 0x70, // movs r0, #0x0100
                    0xc1, 0xf2, 0x00, 0x00, // movt r0, #0x1000
                    0x01, 0x21, // movs r1, #1
                    0x01, 0x60, // str r1, [r0]
                    0x02, 0x68, // ldr r2, [r0]
                    0x00, 0xBF, // nop
                    0x00, 0xBF, // nop for hook
                ],
            )
        ),
        &vec![1.0, 2.0, 1.0, 1.0, 2.0]
    );

    assert_eq!(
        &generate_leakage(
            Box::new(HammingWeightLeakage::new()),
            Segment(
                0x1000_0000,
                vec![
                    0x00, 0xBF, // nop for hook
                    0x5f, 0xf4, 0x80, 0x70, // movs r0, #0x0100
                    0xc1, 0xf2, 0x00, 0x00, // movt r0, #0x1000
                    0x01, 0x21, // movs r1, #1
                    0x01, 0x60, // str r1, [r0]
                    0x0F, 0x22, // movs r2, #0x0F
                    0x02, 0x60, // str r2, [r0]
                    0x1F, 0x23, // movs r3, #0x1F
                    0xFF, 0x24, // movs r4, #0xFF
                    0x80, 0xe8, 0x1e, 0x00, // stm r0, {r1, r2, r3, r4}
                    0x00, 0xBF, // nop
                    0x00, 0xBF, // nop for hook
                ],
            )
        ),
        &vec![1.0, 2.0, 1.0, 1.0, 4.0, 5.0, 5.0, 8.0, 22.0]
    );
}

#[test]
fn test_hamming_distance_leakage() {
    // Test basic hamming weight changes
    assert_eq!(
        &generate_leakage(
            Box::new(HammingDistanceLeakage::new()),
            Segment(
                0x1000_0000,
                vec![
                    0x00, 0xBF, // nop for hook
                    0x01, 0x20, // movs r0, #0x01
                    0x03, 0x20, // movs r0, #0x03
                    0x07, 0x20, // movs r0, #0x07
                    0x0F, 0x20, // movs r0, #0x0F
                    0x00, 0xBF, // nop
                    0x00, 0xBF, // nop for hook
                ],
            )
        ),
        &vec![1.0, 1.0, 1.0, 1.0]
    );
}

#[test]
fn test_hamming_distance_leakage_memory() {
    assert_eq!(
        &generate_leakage(
            Box::new(HammingWeightLeakage::new()),
            Segment(
                0x1000_0000,
                vec![
                    0x00, 0xBF, // nop for hook
                    0x5f, 0xf4, 0x80, 0x70, // movs r0, #0x0100
                    0xc1, 0xf2, 0x00, 0x00, // movt r0, #0x1000
                    0x01, 0x21, // movs r1, #1
                    0x01, 0x60, // str r1, [r0]
                    0x02, 0x68, // ldr r2, [r0]
                    0x00, 0xBF, // nop
                    0x00, 0xBF, // nop for hook
                ],
            )
        ),
        &vec![1.0, 2.0, 1.0, 1.0, 2.0]
    );

    assert_eq!(
        &generate_leakage(
            Box::new(HammingDistanceLeakage::new()),
            Segment(
                0x1000_0000,
                vec![
                    0x00, 0xBF, // nop for hook
                    0x5f, 0xf4, 0x80, 0x70, // movs r0, #0x0100
                    0xc1, 0xf2, 0x00, 0x00, // movt r0, #0x1000
                    0x01, 0x21, // movs r1, #1
                    0x01, 0x60, // str r1, [r0]
                    0x47, 0xf2, 0xFF, 0x72, // mov r2, #0x77ff
                    0xc1, 0xf2, 0x33, 0x12, // movt r2, #0x1133
                    0x02, 0x60, // str r2, [r0]
                    0x42, 0x71, // strb r2, [r0, #5]
                    0xa0, 0xf8, 0x05, 0x20, // strh r2, [r0, #5]
                    0x00, 0xBF, // nop
                    0x00, 0xBF, // nop for hook
                ],
            )
        ),
        &vec![1.0, 1.0, 1.0, 1.0, 14.0, 6.0, 19.0, 8.0, 6.0]
    );
}

#[test]
fn test_victim_communication() {
    let (channel_host, channel_emu) = create_inter_thread_channels();
    let elfinfo = ElfInfo::new_from_binary(vec![Segment(
        0x1000_0000,
        vec![
            0x00, 0xBF, // nop for hook
            0x00, 0xBF, // nop
            0x00, 0xBF, // nop
            0x00, 0xBF, // nop
        ],
    )])
    .unwrap();
    let mut emu = ThumbTraceEmulator::new(
        &elfinfo,
        Box::new(HammingWeightLeakage::new()),
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
        .send(ITCRequest::VictimData(0, vec![1, 2, 3, 4], false))
        .unwrap();

    emu.set_pc(0x1000_0001).unwrap();
    emu.start().unwrap();

    assert!(matches!(
        channel_host.recv().unwrap(),
        ITCResponse::Trace(0, v)
        if v == vec![1.0, 2.0, 3.0, 4.0]
    ))
}

#[test]
fn test_terminate() {
    let (channel_host, channel_emu) = create_inter_thread_channels();
    let elfinfo = ElfInfo::new_from_binary(vec![Segment(
        0x1000_0000,
        vec![
            0x00, 0xBF, // nop for hook
            0x00, 0xBF, // nop
            0x00, 0xBF, // nop
            0x00, 0xBF, // nop
        ],
    )])
    .unwrap();
    let mut emu = ThumbTraceEmulator::new(
        &elfinfo,
        Box::new(HammingWeightLeakage::new()),
        Reflector::new(channel_emu.clone()),
        channel_emu,
    )
    .unwrap();

    emu.mem_map(0x1000_0000, 1024, Permission::all()).unwrap();
    emu.load().unwrap();

    emu.register_hook_addr(0x1000_0000, |emu| emu.process_inter_thread_communication());

    channel_host.send(ITCRequest::Terminate).unwrap();

    emu.set_pc(0x1000_0001).unwrap();
    emu.start().unwrap();
}
