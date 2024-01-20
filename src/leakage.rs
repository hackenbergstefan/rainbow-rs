// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use crate::ScaData;
use log::debug;

pub trait HammingWeight {
    /// Calculation of hamming weight (i.e. number of 1-bits in value)
    fn hamming(self) -> u32;
}

impl HammingWeight for u8 {
    fn hamming(self) -> u32 {
        self.count_ones()
    }
}

impl HammingWeight for u16 {
    fn hamming(self) -> u32 {
        self.count_ones()
    }
}

impl HammingWeight for u32 {
    fn hamming(self) -> u32 {
        self.count_ones()
    }
}

impl HammingWeight for u64 {
    fn hamming(self) -> u32 {
        self.count_ones()
    }
}

impl HammingWeight for u128 {
    fn hamming(self) -> u32 {
        self.count_ones()
    }
}

/// Generic Leakage Model
pub trait LeakageModel {
    /// Calculate the value of the trace point at given instruction
    fn calculate(&self, scadata: &[ScaData]) -> f32;

    /// Calculate leakage value for given memory change
    fn calculate_memory(&mut self, mem_before: u64, mem_after: u64) -> f32;

    /// Number of cycles that are incoporated into the leakage calculation
    fn cycles_for_calc(&self) -> usize;
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
    #[inline]
    fn cycles_for_calc(&self) -> usize {
        1
    }

    fn calculate(&self, scadata: &[ScaData]) -> f32 {
        assert!(scadata.len() == 1);
        let scadata = &scadata[0];
        let regs_before = scadata.regvalues_before.as_ref();
        let regs_after = scadata.regvalues_after.as_ref();
        let val = regs_after
            .iter()
            .zip(regs_before)
            .map(|(&val_after, &val_before)| {
                if val_after != val_before {
                    val_after.hamming() as f32
                } else {
                    0.0
                }
            })
            .sum();
        debug!(
            "Calculate for {:} {:}: {:x?} -> {:x?} => {:?}",
            scadata.instruction.mnemonic().unwrap(),
            scadata.instruction.op_str().unwrap(),
            // instruction_detail.sca_operands(),
            regs_before,
            regs_after,
            val
        );
        val
    }

    fn calculate_memory(&mut self, mem_before: u64, mem_after: u64) -> f32 {
        let val = mem_after.hamming() as f32;
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
    #[inline]
    fn cycles_for_calc(&self) -> usize {
        1
    }

    fn calculate(&self, scadata: &[ScaData]) -> f32 {
        assert!(scadata.len() == 1);
        let scadata = &scadata[0];
        let regs_before = scadata.regvalues_before.as_ref();
        let regs_after = scadata.regvalues_after.as_ref();
        let val = regs_after
            .iter()
            .zip(regs_before)
            .map(|(&val_after, &val_before)| (val_after ^ val_before).hamming() as f32)
            .sum();
        debug!(
            "Calculate for {:} {:}: {:x?} -> {:x?} => {:?}",
            scadata.instruction.mnemonic().unwrap(),
            scadata.instruction.op_str().unwrap(),
            // instruction_detail.sca_operands(),
            regs_before,
            regs_after,
            val
        );
        val
    }

    fn calculate_memory(&mut self, mem_before: u64, mem_after: u64) -> f32 {
        (mem_before ^ mem_after).hamming() as f32
    }
}
