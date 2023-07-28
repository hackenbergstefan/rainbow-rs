// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use capstone::{arch::arm::ArmInsnDetail, Insn};
use log::debug;

use crate::asmutils::SideChannelOperands;

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

    /// Calculate leakage value for given memory change
    fn calculate_memory(&self, mem_before: u64, mem_after: u64) -> f32;
}

/// Hamming Weight leakage.
/// HammingWeightLeakage leaks the hamming weight of newly written registers
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
            .zip(regs_before)
            .map(|(&val_after, &val_before)| {
                if val_after != val_before {
                    hamming_weight(val_after as u32) as f32
                } else {
                    0.0
                }
            })
            .sum();
        debug!(
            "Calculate for {:} {:} {:?}: {:x?} -> {:x?} => {:?}",
            instruction.mnemonic().unwrap(),
            instruction.op_str().unwrap(),
            instruction_detail.sca_operands(),
            regs_before,
            regs_after,
            val
        );
        val
    }

    fn calculate_memory(&self, mem_before: u64, mem_after: u64) -> f32 {
        let val = hamming_weight(mem_after as u32) as f32;
        debug!("HammingWeightLeakage::calculate_memory {mem_before:08x} {mem_after:08x} => {val}");
        val
    }
}

/// Hamming Distance leakage.
/// HammingDistanceLeakage leaks the hamming distance of changed registers
pub struct HammingDistanceLeakage {}

impl HammingDistanceLeakage {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for HammingDistanceLeakage {
    fn default() -> Self {
        Self::new()
    }
}

impl LeakageModel for HammingDistanceLeakage {
    fn calculate(
        &self,
        instruction: &Insn,
        instruction_detail: &ArmInsnDetail,
        regs_before: &[u64],
        regs_after: &[u64],
    ) -> f32 {
        let val = regs_after
            .iter()
            .zip(regs_before)
            .map(|(&val_after, &val_before)| hamming_weight((val_after ^ val_before) as u32) as f32)
            .sum();
        debug!(
            "Calculate for {:} {:} {:?}: {:x?} -> {:x?} => {:?}",
            instruction.mnemonic().unwrap(),
            instruction.op_str().unwrap(),
            instruction_detail.sca_operands(),
            regs_before,
            regs_after,
            val
        );
        val
    }

    fn calculate_memory(&self, mem_before: u64, mem_after: u64) -> f32 {
        hamming_weight((mem_before ^ mem_after) as u32) as f32
    }
}
