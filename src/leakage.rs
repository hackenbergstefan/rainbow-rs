// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use capstone::{arch::arm::ArmOperandType, prelude::DetailsArchInsn, Insn, InsnDetail};
use log::debug;

use super::trace_emulator::regid2regindex;
use super::trace_emulator::THUMB_TRACE_REGISTERS;

/// Calculation of hamming weight (i.e. number of 1-bits in value)
pub fn hamming_weight(value: u32) -> u32 {
    value.count_ones()
}

/// Generic Leakage Model
pub trait LeakageModel {
    /// Calculate the value of the trace point at given instruction
    fn calculate(
        &self,
        instruction: &Insn,
        instruction_detail: &InsnDetail,
        last_values: &[u32; THUMB_TRACE_REGISTERS.len()],
        values: &[u32; THUMB_TRACE_REGISTERS.len()],
    ) -> f32;
}

/// Hamming Weight leakage.
/// HammingWeightLeakage leaks the hamming weight of every changed register value
pub struct HammingWeightLeakage {}

impl HammingWeightLeakage {
    pub fn new() -> Self {
        Self {}
    }
}

impl LeakageModel for HammingWeightLeakage {
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
            // instruction_detail
            //     .arch_detail()
            //     .arm()
            //     .unwrap()
            //     .operands()
            //     .collect::<Vec<ArmOperand>>(),
        );
        let mut val = 0.0;
        for operand in instruction_detail.arch_detail().arm().unwrap().operands() {
            if let ArmOperandType::Reg(r) = operand.op_type {
                if let Some((i, reg)) = regid2regindex(r) {
                    debug!("    {:?}: {:08x}", reg, values[i]);
                    val += hamming_weight(values[i]) as f32;
                }
            }
        }
        val
    }
}
