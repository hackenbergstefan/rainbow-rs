// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use capstone::{arch::arm::ArmInsnDetail, Insn};
use log::debug;

use crate::asmutils::ModifiedRegs;

/// Calculation of hamming weight (i.e. number of 1-bits in value)
#[inline]
pub fn hamming_weight(value: u32) -> u32 {
    value.count_ones()
}

/// Generic Leakage Model
pub trait LeakageModel {
    /// Calculate the value of the trace point at given instruction
    fn calculate(
        &self,
        instruction: &Insn,
        instruction_detail: &ArmInsnDetail,
        regs_before: &[u64],
        regs_after: &[u64],
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

impl Default for HammingWeightLeakage {
    fn default() -> Self {
        Self::new()
    }
}

impl LeakageModel for HammingWeightLeakage {
    fn calculate(
        &self,
        instruction: &Insn,
        instruction_detail: &ArmInsnDetail,
        regs_before: &[u64],
        regs_after: &[u64],
    ) -> f32 {
        let val = regs_after
            .iter()
            .map(|val| hamming_weight(*val as u32) as f32)
            .sum();
        debug!(
            "Calculate for {:} {:} {:?}: {:?} -> {:?} => {:?}",
            instruction.mnemonic().unwrap(),
            instruction.op_str().unwrap(),
            instruction_detail.get_regs(),
            regs_before,
            regs_after,
            val
        );
        val
    }
}
