use capstone::{arch::arm::ArmOperandType, prelude::DetailsArchInsn, Insn, InsnDetail};
use log::debug;

use super::trace_emulator::regid2regindex;
use super::trace_emulator::THUMB_TRACE_REGISTERS;

pub fn hamming_weight(val: u32) -> u32 {
    val.count_ones()
}

pub trait LeakageModel {
    fn calculate(
        &self,
        instruction: &Insn,
        instruction_detail: &InsnDetail,
        last_values: &[u32; THUMB_TRACE_REGISTERS.len()],
        values: &[u32; THUMB_TRACE_REGISTERS.len()],
    ) -> f32;
}

pub struct HammingWeightLeakage {}

impl HammingWeightLeakage {
    pub fn new() -> Self {
        Self {}
    }
}

impl LeakageModel for HammingWeightLeakage {
    /// HW leakage leaks the hamming weight of every changed register value
    fn calculate(
        &self,
        instruction: &Insn,
        instruction_detail: &InsnDetail,
        _last_values: &[u32; THUMB_TRACE_REGISTERS.len()],
        values: &[u32; THUMB_TRACE_REGISTERS.len()],
    ) -> f32 {
        debug!(
            "Calculate for {:} {:}",
            instruction.mnemonic().unwrap(),
            instruction.op_str().unwrap(),
            // instruction_detail.arch_detail().arm().unwrap().operands(),
        );
        let mut val = 0.0;
        for operand in instruction_detail.arch_detail().arm().unwrap().operands() {
            if let ArmOperandType::Reg(r) = operand.op_type {
                if let Some((i, reg)) = regid2regindex(r) {
                    println!("    {:?}: {:08x}", reg, values[i]);
                    val += hamming_weight(values[i]) as f32;
                }
            }
        }
        val
    }
}
