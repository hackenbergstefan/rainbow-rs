// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use crate::ScaData;
use capstone::{arch::arm::ArmInsn, OwnedInsn};
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
        if current_instruction_type == 5 {
            return self.coefficients.constant[0] as f32;
        }

        let current0 = current.get(0).or(Some(&0)).unwrap();
        let current1 = current.get(1).or(Some(&0)).unwrap();
        let previous0 = previous.get(0).or(Some(&0)).unwrap();
        let previous1 = previous.get(1).or(Some(&0)).unwrap();

        let hw_op1 = current0.hamming();
        let hw_op2 = current1.hamming();

        let hd_op1 = (current0 ^ previous0).hamming();
        let hd_op2 = (current1 ^ previous1).hamming();

        let bitflips_op1 = current0 ^ previous0;
        let bitflips_op2 = current1 ^ previous1;

        // Calculate leakage for each bit
        let op1_data: f64 = (0..32)
            .map(|i| {
                ((current0 >> i) & 1) as f64
                    * self.coefficients.operand1[i][current_instruction_type]
            })
            .sum();
        let op2_data: f64 = (0..32)
            .map(|i| {
                ((current1 >> i) & 1) as f64
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

        if previous_instruction_type > 0 && previous_instruction_type < 5 {
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

        if subsequent_instruction_type > 0 && subsequent_instruction_type < 5 {
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

    pub fn instruction_type(instruction: &OwnedInsn) -> usize {
        let id = instruction.id().0;
        match id {
            id if id == ArmInsn::ARM_INS_ADD as u32 => 0,
            id if id == ArmInsn::ARM_INS_SUB as u32 => 0,
            id if id == ArmInsn::ARM_INS_AND as u32 => 0,
            id if id == ArmInsn::ARM_INS_CMP as u32 => 0,
            id if id == ArmInsn::ARM_INS_CPS as u32 => 0,
            id if id == ArmInsn::ARM_INS_EOR as u32 => 0,
            id if id == ArmInsn::ARM_INS_MOV as u32 => 0,
            id if id == ArmInsn::ARM_INS_ORR as u32 => 0,

            id if id == ArmInsn::ARM_INS_LSL as u32 => 1,
            id if id == ArmInsn::ARM_INS_LSR as u32 => 1,
            id if id == ArmInsn::ARM_INS_ROR as u32 => 1,

            id if id == ArmInsn::ARM_INS_STR as u32 => 2,
            id if id == ArmInsn::ARM_INS_STRH as u32 => 2,
            id if id == ArmInsn::ARM_INS_STRB as u32 => 2,

            id if id == ArmInsn::ARM_INS_LDR as u32 => 3,
            id if id == ArmInsn::ARM_INS_LDRH as u32 => 3,
            id if id == ArmInsn::ARM_INS_LDRB as u32 => 3,

            id if id == ArmInsn::ARM_INS_MUL as u32 => 4,
            _ => 5,
        }
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
            ElmoPowerLeakage::instruction_type(scadata[0].instruction),
            ElmoPowerLeakage::instruction_type(scadata[1].instruction),
            ElmoPowerLeakage::instruction_type(scadata[2].instruction),
            scadata[0].regvalues_before.as_ref(),
            scadata[1].regvalues_before.as_ref(),
            scadata[2].regvalues_before.as_ref(),
        );
    }

    fn calculate_memory(&mut self, mem_before: u64, mem_after: u64) -> f32 {
        0.0
    }
}
