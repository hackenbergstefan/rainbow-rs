// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use std::iter;

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

struct ElmoPowerLeakageCoefficients {
    constant: [f64; 5],
    previous_instructions: [[f64; 5]; 4],
    subsequent_instructions: [[f64; 5]; 4],
    operand1: [[f64; 5]; 32],
    operand2: [[f64; 5]; 32],
    bitflip1: [[f64; 5]; 32],
    bitflip2: [[f64; 5]; 32],
    hw_operand1_previous_instruction: [[f64; 5]; 4],
    hw_operand2_previous_instruction: [[f64; 5]; 4],
    hd_operand1_previous_instruction: [[f64; 5]; 4],
    hd_operand2_previous_instruction: [[f64; 5]; 4],
    hw_operand1_subsequent_instruction: [[f64; 5]; 4],
    hw_operand2_subsequent_instruction: [[f64; 5]; 4],
    hd_operand1_subsequent_instruction: [[f64; 5]; 4],
    hd_operand2_subsequent_instruction: [[f64; 5]; 4],
}

impl ElmoPowerLeakageCoefficients {
    pub fn new(coefficient_file: &str) -> Self {
        let mut coefficients = Self {
            constant: [0.0; 5],
            previous_instructions: [[0.0; 5]; 4],
            subsequent_instructions: [[0.0; 5]; 4],
            operand1: [[0.0; 5]; 32],
            operand2: [[0.0; 5]; 32],
            bitflip1: [[0.0; 5]; 32],
            bitflip2: [[0.0; 5]; 32],
            hw_operand1_previous_instruction: [[0.0; 5]; 4],
            hw_operand2_previous_instruction: [[0.0; 5]; 4],
            hd_operand1_previous_instruction: [[0.0; 5]; 4],
            hd_operand2_previous_instruction: [[0.0; 5]; 4],
            hw_operand1_subsequent_instruction: [[0.0; 5]; 4],
            hw_operand2_subsequent_instruction: [[0.0; 5]; 4],
            hd_operand1_subsequent_instruction: [[0.0; 5]; 4],
            hd_operand2_subsequent_instruction: [[0.0; 5]; 4],
        };

        for (line, coeffs) in std::fs::read_to_string(coefficient_file)
            .expect("Could not read coefficient file")
            .lines()
            .zip(coefficients.iter_mut())
        {
            let coeff_line: Vec<f64> = line
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            assert!(coeff_line.len() == 5);
            coeffs.copy_from_slice(&coeff_line[..]);
        }

        coefficients
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = &mut [f64; 5]> {
        std::iter::once(&mut self.constant)
            .chain(self.previous_instructions.iter_mut())
            .chain(self.subsequent_instructions.iter_mut())
            .chain(self.operand1.iter_mut())
            .chain(self.operand2.iter_mut())
            .chain(self.bitflip1.iter_mut())
            .chain(self.bitflip2.iter_mut())
            .chain(self.hw_operand1_previous_instruction.iter_mut())
            .chain(self.hw_operand2_previous_instruction.iter_mut())
            .chain(self.hd_operand1_previous_instruction.iter_mut())
            .chain(self.hd_operand2_previous_instruction.iter_mut())
            .chain(self.hw_operand1_subsequent_instruction.iter_mut())
            .chain(self.hw_operand2_subsequent_instruction.iter_mut())
            .chain(self.hd_operand1_subsequent_instruction.iter_mut())
            .chain(self.hd_operand2_subsequent_instruction.iter_mut())
    }
}

/// Elmo Power Leakage Model
pub struct ElmoPowerLeakage {
    coefficients: ElmoPowerLeakageCoefficients,
}

impl ElmoPowerLeakage {
    pub fn new(coefficient_file: &str) -> Self {
        Self {
            coefficients: ElmoPowerLeakageCoefficients::new(coefficient_file),
        }
    }

    fn calculate_powermodel(
        &self,
        previous_instruction_type: usize,
        current_instruction_type: usize,
        subsequent_instruction_type: usize,
        previous: &[u64],
        current: &[u64],
        _subsequent: &[u64],
    ) -> f32 {
        let hw_op1 = current[0].hamming();
        let hw_op2 = current[1].hamming();

        let hd_op1 = (current[0] ^ previous[0]).hamming();
        let hd_op2 = (current[1] ^ previous[1]).hamming();

        let bitflips_op1 = current[0] ^ previous[0];
        let bitflips_op2 = current[1] ^ previous[1];

        // Calculate leakage for each bit
        let op1_data: f64 = (0..32)
            .map(|i| {
                ((current[0] >> i) & 1) as f64
                    * self.coefficients.operand1[i][current_instruction_type]
            })
            .sum();
        let op2_data: f64 = (0..32)
            .map(|i| {
                ((current[1] >> i) & 1) as f64
                    * self.coefficients.operand2[i][current_instruction_type]
            })
            .sum();

        let bitflip1_data: f64 = (0..32)
            .map(|i| {
                ((bitflips_op1 >> i) & 1) as f64
                    * self.coefficients.bitflip1[i][current_instruction_type]
            })
            .sum();
        let bitflip2_data: f64 = (0..32)
            .map(|i| {
                ((bitflips_op2 >> i) & 1) as f64
                    * self.coefficients.bitflip2[i][current_instruction_type]
            })
            .sum();

        // Calculate leakage depending on instruction type
        // TODO: No idea where i+1 in the original code comes from
        let mut previous_instruction_data: f64 = 0.0;
        let mut hw_op1_previous_instruction_data: f64 = 0.0;
        let mut hw_op2_previous_instruction_data: f64 = 0.0;
        let mut hd_op1_previous_instruction_data: f64 = 0.0;
        let mut hd_op2_previous_instruction_data: f64 = 0.0;

        if previous_instruction_type > 0 {
            previous_instruction_data = self.coefficients.previous_instructions
                [previous_instruction_type - 1][current_instruction_type];
            hw_op1_previous_instruction_data = self.coefficients.hw_operand1_previous_instruction
                [previous_instruction_type - 1][current_instruction_type]
                * hw_op1 as f64;
            hw_op2_previous_instruction_data = self.coefficients.hw_operand2_previous_instruction
                [previous_instruction_type - 1][current_instruction_type]
                * hw_op2 as f64;
            hd_op1_previous_instruction_data = self.coefficients.hd_operand1_previous_instruction
                [previous_instruction_type - 1][current_instruction_type]
                * hd_op1 as f64;
            hd_op2_previous_instruction_data = self.coefficients.hd_operand2_previous_instruction
                [previous_instruction_type - 1][current_instruction_type]
                * hd_op2 as f64;
        }

        let mut subsequent_instruction_data: f64 = 0.0;
        let mut hw_op1_subsequent_instruction_data: f64 = 0.0;
        let mut hw_op2_subsequent_instruction_data: f64 = 0.0;
        let mut hd_op1_subsequent_instruction_data: f64 = 0.0;
        let mut hd_op2_subsequent_instruction_data: f64 = 0.0;

        if subsequent_instruction_type > 0 {
            subsequent_instruction_data = self.coefficients.subsequent_instructions
                [subsequent_instruction_type - 1][current_instruction_type];
            hw_op1_subsequent_instruction_data =
                self.coefficients.hw_operand1_subsequent_instruction
                    [subsequent_instruction_type - 1][current_instruction_type]
                    * hw_op1 as f64;
            hw_op2_subsequent_instruction_data =
                self.coefficients.hw_operand2_subsequent_instruction
                    [subsequent_instruction_type - 1][current_instruction_type]
                    * hw_op2 as f64;
            hd_op1_subsequent_instruction_data =
                self.coefficients.hd_operand1_subsequent_instruction
                    [subsequent_instruction_type - 1][current_instruction_type]
                    * hd_op1 as f64;
            hd_op2_subsequent_instruction_data =
                self.coefficients.hd_operand2_subsequent_instruction
                    [subsequent_instruction_type - 1][current_instruction_type]
                    * hd_op2 as f64;
        }

        let leakage = self.coefficients.constant[current_instruction_type]
            + op1_data
            + op2_data
            + bitflip1_data
            + bitflip2_data
            + previous_instruction_data
            + subsequent_instruction_data
            + hw_op1_previous_instruction_data
            + hw_op2_previous_instruction_data
            + hd_op1_previous_instruction_data
            + hd_op2_previous_instruction_data
            + hw_op1_subsequent_instruction_data
            + hw_op2_subsequent_instruction_data
            + hd_op1_subsequent_instruction_data
            + hd_op2_subsequent_instruction_data;

        leakage as f32
    }
}

impl LeakageModel for ElmoPowerLeakage {
    #[inline]
    fn cycles_for_calc(&self) -> usize {
        3
    }

    fn calculate(&self, scadata: &[ScaData]) -> f32 {
        assert!(scadata.len() == 3);
        return self.calculate_powermodel(
            0,
            0,
            0,
            scadata[0].regvalues_before.as_ref(),
            scadata[1].regvalues_before.as_ref(),
            scadata[2].regvalues_before.as_ref(),
        );
    }

    fn calculate_memory(&mut self, mem_before: u64, mem_after: u64) -> f32 {
        0.0
    }
}
