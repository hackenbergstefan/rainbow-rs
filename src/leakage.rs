// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use crate::ScaData;
use arrayvec::ArrayVec;
use capstone::{arch::arm::ArmInsn, OwnedInsn};
use itertools::{iproduct, Itertools};
use log::{debug, info};

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

#[derive(Debug)]
pub struct Leakage<'a> {
    pub instruction: &'a OwnedInsn<'static>,
    pub values: ArrayVec<f32, 16>,
}

/// Generic Leakage Model
pub trait LeakageModel {
    /// Calculate the value of the trace point at given instruction
    fn calculate<'a>(&mut self, scadata: &[ScaData<'a>]) -> Leakage<'a>;

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

    fn calculate<'a>(&mut self, scadata: &[ScaData<'a>]) -> Leakage<'a> {
        debug!("Calculate HammingWeightLeakage for {:?}", scadata);

        assert!(scadata.len() == 1);
        let scadata = &scadata[0];

        // Process register leakage
        let mut register_leakage = {
            let regs_before = scadata.regvalues_before.as_ref();
            let regs_after = scadata.regvalues_after.as_ref();
            regs_after
                .iter()
                .zip(regs_before)
                .map(|(&val_after, &val_before)| {
                    if val_after != val_before {
                        val_after.hamming() as f32
                    } else {
                        0.0
                    }
                })
                .sum()
        };

        // Process memory leakage
        if !scadata.memory_before.is_empty() {
            register_leakage += scadata
                .memory_before
                .iter()
                .map(|x| x.hamming())
                .sum::<u32>() as f32;
            register_leakage += scadata
                .memory_after
                .iter()
                .map(|x| x.hamming())
                .sum::<u32>() as f32;
        }

        let mut leakage = Leakage {
            instruction: scadata.instruction,
            values: ArrayVec::new(),
        };
        leakage.values.push(register_leakage);
        leakage
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

    fn calculate<'a>(&mut self, scadata: &[ScaData<'a>]) -> Leakage<'a> {
        assert!(scadata.len() == 1);
        let scadata = &scadata[0];
        let mut register_leakage = {
            let regs_before = scadata.regvalues_before.as_ref();
            let regs_after = scadata.regvalues_after.as_ref();
            regs_after
                .iter()
                .zip(regs_before)
                .map(|(&val_after, &val_before)| (val_after ^ val_before).hamming() as f32)
                .sum()
        };

        // Process memory leakage
        register_leakage += scadata
            .memory_before
            .iter()
            .zip(scadata.memory_after.iter())
            .map(|(before, after)| (before ^ after).hamming())
            .sum::<u32>() as f32;

        let mut leakage = Leakage {
            instruction: scadata.instruction,
            values: ArrayVec::new(),
        };
        leakage.values.push(register_leakage);
        leakage
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
    readbus: u64,
    writebus: u64,
    resistance: f32,
    supplyvoltage: f32,
}

impl ElmoPowerLeakage {
    pub fn new(coefficient_file: &str) -> Self {
        Self {
            coefficients: ElmoPowerLeakageCoefficients::new(coefficient_file),
            readbus: 0,
            writebus: 0,
            resistance: 360.0,
            supplyvoltage: 3.0,
        }
    }

    fn calculate_powermodel(
        &self,
        previous: &ScaData,
        current: &ScaData,
        subsequent: &ScaData,
    ) -> f32 {
        let current_instruction_type = ElmoPowerLeakage::instruction_type(current.instruction);
        let previous_instruction_type = ElmoPowerLeakage::instruction_type(previous.instruction);
        let subsequent_instruction_type =
            ElmoPowerLeakage::instruction_type(subsequent.instruction);

        if current_instruction_type == 5 {
            let leakage =
                self.coefficients.constant[0] as f32 / self.resistance * self.supplyvoltage;
            // warn!("instructiontype: {:} op1: {:08x} op2: {:08x} prev_op1: {:08x} prev_op2: {:08x} -> {:1.3e} current: {:} {:}", current_instruction_type,
            //     0,0,0,0, leakage, current.instruction.mnemonic().unwrap(), current.instruction.op_str().unwrap());
            return leakage;
        }

        let mut current0 = 0;
        let mut current1 = 0;
        let len = current.regvalues_before.len();
        if len >= 2 {
            current0 = current.regvalues_before[len - 1];
            current1 = current.regvalues_before[len - 2];
        } else if len > 0 {
            current0 = current.regvalues_before[len - 1];
        }

        let mut previous0 = 0;
        let mut previous1 = 0;
        let len = previous.regvalues_before.len();
        if len >= 2 {
            previous0 = previous.regvalues_before[len - 1];
            previous1 = previous.regvalues_before[len - 2];
        } else if len > 0 {
            previous0 = previous.regvalues_before[len - 1];
        }

        {
            if !current.memory_after.is_empty() {
                current0 = *current.memory_before.last().unwrap();
                current1 = *current.memory_after.last().unwrap();
            } else if !current.memory_before.is_empty() {
                current1 = *current.memory_before.last().unwrap();
            }
            if !previous.memory_after.is_empty() {
                previous0 = *previous.memory_before.last().unwrap();
                previous1 = *previous.memory_after.last().unwrap();
            } else if !previous.memory_before.is_empty() {
                previous1 = *previous.memory_before.last().unwrap();
            }
        }

        let hw_op1 = current0.hamming();
        let hw_op2 = current1.hamming();

        let hd_op1 = (current0 ^ previous0).hamming();
        let hd_op2 = (current1 ^ previous1).hamming();

        let bitflips_op1 = current0 ^ previous0;
        let bitflips_op2 = current1 ^ previous1;

        let hd_op = (current0 ^ current1).hamming();

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
        let op_data: f64 = (0..32)
            .map(|i| {
                ((hd_op >> i) & 1) as f64 * self.coefficients.bitflip2[i][current_instruction_type]
            })
            .sum();
        let op_data = 20.0 * op_data;

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

        let mut leakage = self.coefficients.constant[current_instruction_type]
            + op_data
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

        // Add memory leakage
        let memory_leakage = {
            if !current.memory_after.is_empty() {
                std::iter::once(&self.writebus)
                    .chain(current.memory_after.iter())
                    .zip(current.memory_after.iter())
                    .map(|(before, after)| {
                        self.coefficients.hd_operand1_previous_instruction[0]
                            [current_instruction_type]
                            * (before ^ after).hamming() as f64
                    })
                    .sum::<f64>()
            } else {
                std::iter::once(&self.readbus)
                    .chain(current.memory_before.iter())
                    .zip(current.memory_before.iter())
                    .map(|(before, after)| {
                        self.coefficients.hd_operand1_previous_instruction[0]
                            [current_instruction_type]
                            * (before ^ after).hamming() as f64
                    })
                    .sum()
            }
        };

        leakage += memory_leakage;

        let leakage = leakage as f32 / self.resistance * self.supplyvoltage;

        info!(
            "{:} {:} instructiontype: {:} op1: {:08x} op2: {:08x} prev_op1: {:08x} prev_op2: {:08x} -> {:1.3e}
    op1_data: {:1.3e}
    op2_data: {:1.3e}
    bitflip1_data: {:1.3e}
    bitflip2_data: {:1.3e}
    previous_instruction_data: {:1.3e}
    subsequent_instruction_data: {:1.3e}
    hw_op1_previous_instruction_data: {:1.3e}
    hw_op2_previous_instruction_data: {:1.3e}
    hd_op1_previous_instruction_data: {:1.3e}
    hd_op2_previous_instruction_data: {:1.3e}
    hw_op1_subsequent_instruction_data: {:1.3e}
    hw_op2_subsequent_instruction_data: {:1.3e}
    hd_op1_subsequent_instruction_data: {:1.3e}
    hd_op2_subsequent_instruction_data: {:1.3e}
    memory_leakage: {:1.3e}
    readbus: {:?} writebus: {:?} {:?}",
            current.instruction.mnemonic().unwrap(),
            current.instruction.op_str().unwrap(),
            current_instruction_type,
            current0,
            current1,
            previous0,
            previous1,
            leakage,
            op1_data,
            op2_data,
            bitflip1_data,
            bitflip2_data,
            previous_instruction_data,
            subsequent_instruction_data,
            hw_op1_previous_instruction_data,
            hw_op2_previous_instruction_data,
            hd_op1_previous_instruction_data,
            hd_op2_previous_instruction_data,
            hw_op1_subsequent_instruction_data,
            hw_op2_subsequent_instruction_data,
            hd_op1_subsequent_instruction_data,
            hd_op2_subsequent_instruction_data,
            memory_leakage,
            self.readbus,
            self.writebus,
            current,
        );

        leakage
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
            id if id == ArmInsn::ARM_INS_MOVS as u32 => 0,
            id if id == ArmInsn::ARM_INS_MOVT as u32 => 0,
            id if id == ArmInsn::ARM_INS_MOVW as u32 => 0,
            id if id == ArmInsn::ARM_INS_ORR as u32 => 0,
            id if id == ArmInsn::ARM_INS_HINT as u32 => 0,
            id if id == ArmInsn::ARM_INS_NOP as u32 => 0,

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

    fn calculate<'a>(&mut self, scadata: &[ScaData<'a>]) -> Leakage<'a> {
        assert!(scadata.len() == 3);
        let leakage_value = self.calculate_powermodel(&scadata[0], &scadata[1], &scadata[2]);

        let mut leakage = Leakage {
            instruction: scadata[1].instruction,
            values: ArrayVec::new(),
        };
        leakage.values.push(leakage_value);

        // Append further values for cycle accurate memory operations
        for _ in 0..scadata[1].memory_before.len() {
            leakage.values.push(leakage_value);
        }

        // Update memory busses
        {
            let current_data = &scadata[1];
            if !current_data.memory_after.is_empty() {
                self.writebus = *current_data.memory_after.last().unwrap();
            } else if !current_data.memory_before.is_empty() {
                self.readbus = *current_data.memory_before.last().unwrap();
            }
        }

        leakage
    }
}

pub struct PessimisticHammingLeakage {
    busvalue: u64,
}

impl PessimisticHammingLeakage {
    pub fn new() -> Self {
        PessimisticHammingLeakage { busvalue: 0 }
    }
}

impl LeakageModel for PessimisticHammingLeakage {
    #[inline]
    fn cycles_for_calc(&self) -> usize {
        2
    }

    fn calculate<'a>(&mut self, scadata: &[ScaData<'a>]) -> Leakage<'a> {
        assert!(scadata.len() == 2);

        let mut leakage = 0;
        let current_data = &scadata[1];
        let previous_data = &scadata[0];

        // Leak hamming weight of all operands
        {
            leakage += current_data
                .regvalues_before
                .iter()
                .map(|x| x.hamming())
                .sum::<u32>();
            leakage += current_data
                .regvalues_after
                .iter()
                .map(|x| x.hamming())
                .sum::<u32>();
        }

        // Leak hamming distance of all operands
        {
            leakage += current_data
                .regvalues_before
                .iter()
                .combinations(2)
                .map(|x| (x[0] ^ x[1]).hamming())
                .sum::<u32>();
            leakage += current_data
                .regvalues_after
                .iter()
                .combinations(2)
                .map(|x| (x[0] ^ x[1]).hamming())
                .sum::<u32>();
        }

        // Leak hamming distance of before and after
        {
            leakage += current_data
                .regvalues_before
                .iter()
                .zip(current_data.regvalues_after.iter())
                .map(|(x, y)| (x ^ y).hamming())
                .sum::<u32>();
        }

        // Leak hamming distance from previous to current
        {
            leakage += iproduct!(
                current_data.regvalues_before.iter(),
                previous_data.regvalues_after.iter()
            )
            .map(|(x, y)| (x ^ y).hamming())
            .sum::<u32>();
        }

        // Leak memory values
        {
            leakage += iproduct!(
                current_data.memory_before.iter(),
                current_data.memory_after.iter()
            )
            .map(|(x, y)| (x ^ y).hamming())
            .sum::<u32>();

            if !current_data.memory_before.is_empty() {
                leakage += iproduct!(
                    std::iter::once(self.busvalue),
                    current_data.memory_before.iter()
                )
                .map(|(x, y)| (x ^ y).hamming())
                .sum::<u32>();
            }
            if !current_data.memory_after.is_empty() {
                self.busvalue = *current_data.memory_after.last().unwrap();
            } else if !current_data.memory_before.is_empty() {
                self.busvalue = *current_data.memory_before.last().unwrap();
            }
        }

        let mut values = ArrayVec::new();
        values.push(leakage as f32);
        Leakage {
            instruction: current_data.instruction,
            values: values,
        }
    }
}
