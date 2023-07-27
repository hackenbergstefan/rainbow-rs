// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use capstone::{
    arch::arm::ArmInsnDetail,
    prelude::{BuildsCapstone, DetailsArchInsn},
    Capstone, OwnedInsn, RegId,
};
use elf::{endian::AnyEndian, ElfBytes};
use unicorn_engine::Unicorn;

use crate::error::CapstoneError;

fn segments(elfbytes: &ElfBytes<AnyEndian>) -> Result<Vec<Segment>> {
    Ok(elfbytes
        .segments()
        .unwrap()
        .into_iter()
        .map(|header| {
            elfbytes
                .segment_data(&header)
                .map(|prog| Segment(header.p_paddr, prog.to_vec()))
        })
        .collect::<std::result::Result<_, _>>()?)
}

fn create_instruction_map<'a>(
    segments: impl Iterator<Item = &'a Segment>,
) -> Result<BTreeMap<u64, (OwnedInsn<'static>, Vec<RegId>)>> {
    let mut map = BTreeMap::new();

    let capstone = Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()
        .unwrap();

    for Segment(addr, data) in segments {
        let instructions = capstone
            .disasm_all(data, *addr)
            .map_err(CapstoneError::new)?;
        for insn in instructions.iter() {
            let insn_detail = capstone.insn_detail(insn).unwrap();
            let insn_detail = insn_detail.arch_detail();
            let insn_detail = insn_detail.arm().unwrap();
            let addr = insn.address();
            map.insert(addr, (OwnedInsn::from(insn), insn_detail.get_regs()));
        }
    }
    Ok(map)
}

fn create_symbolmap(elfbytes: &ElfBytes<AnyEndian>) -> Result<BTreeMap<String, u64>> {
    let mut map = BTreeMap::new();
    let (symtable, strtable) = elfbytes.symbol_table()?.context("Not found")?;
    for symbol in symtable {
        map.insert(
            strtable.get(symbol.st_name as usize)?.to_owned(),
            symbol.st_value,
        );
    }
    Ok(map)
}

pub struct ElfInfo {
    data: Vec<Segment>,
    symbol_map: Option<BTreeMap<String, u64>>,
    instruction_map: BTreeMap<u64, (OwnedInsn<'static>, Vec<RegId>)>,
}

impl ElfInfo {
    pub fn new_from_elffile(elffile: &[u8]) -> Result<Self> {
        let elfbytes = ElfBytes::<AnyEndian>::minimal_parse(elffile)?;
        let segments = segments(&elfbytes)?;
        let symbol_map = create_symbolmap(&elfbytes)?;
        let instruction_map = create_instruction_map(segments.iter())?;

        Ok(ElfInfo {
            data: segments,
            symbol_map: Some(symbol_map),
            instruction_map,
        })
    }

    /// Create ElfInfo without elf-file.
    /// No symbols available!
    pub fn new_from_binary(data: Vec<Segment>) -> Result<Self> {
        Ok(ElfInfo {
            data: data.clone(),
            symbol_map: None,
            instruction_map: create_instruction_map(data.iter())?,
        })
    }

    pub fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.data.iter()
    }

    pub fn get_symbol(&self, name: &str) -> Option<u64> {
        if let Some(symbol_map) = self.symbol_map.as_ref() {
            symbol_map.get(name).copied()
        } else {
            None
        }
    }

    pub fn get_instruction<'a>(
        &'a self,
        address: &u64,
    ) -> Option<&'a (OwnedInsn<'static>, Vec<RegId>)> {
        self.instruction_map.get(address)
        // .and_then(|(ins, regs)| Some((OwnedInsn::from(ins.deref()), regs)))
    }
}

unsafe impl Send for ElfInfo {}
unsafe impl Sync for ElfInfo {}

#[derive(Clone)]
pub struct Segment(pub u64, pub Vec<u8>);

pub trait ModifiedRegs {
    fn get_regs(&self) -> Vec<RegId>;
    fn get_regs_values<D>(&self, emu: &Unicorn<D>) -> Vec<(RegId, u64)>;
}

impl ModifiedRegs for ArmInsnDetail<'_> {
    fn get_regs(&self) -> Vec<RegId> {
        let mut result = Vec::with_capacity(4);
        for operand in self.operands() {
            match operand.op_type {
                capstone::arch::arm::ArmOperandType::Reg(regid) => {
                    result.push(regid);
                }
                capstone::arch::arm::ArmOperandType::Mem(_mem) => {
                    // result.push((regid, emu.reg_read(regid.0)));
                    // TODO
                }
                _ => {}
            }
        }
        result
    }

    fn get_regs_values<D>(&self, emu: &Unicorn<D>) -> Vec<(RegId, u64)> {
        self.get_regs()
            .into_iter()
            .map(|regid| (regid, emu.reg_read(regid.0).unwrap()))
            .collect()
    }
}
