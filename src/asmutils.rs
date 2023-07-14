// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use capstone::{prelude::BuildsCapstone, Capstone, OwnedInsn};
use elf::{endian::AnyEndian, ElfBytes, ParseError};

use crate::error::CapstoneError;

fn iter_segments<'a>(
    elfbytes: &'a ElfBytes<AnyEndian>,
) -> impl Iterator<Item = Result<(u64, &'a [u8]), ParseError>> {
    elfbytes.segments().unwrap().into_iter().map(|header| {
        elfbytes
            .segment_data(&header)
            .map(|prog| (header.p_paddr, prog))
    })
}

fn create_instruction_map<'a>(
    elfbytes: &ElfBytes<AnyEndian>,
) -> Result<BTreeMap<u64, OwnedInsn<'a>>> {
    let mut map = BTreeMap::new();

    let capstone = Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()
        .unwrap();

    for result in iter_segments(elfbytes) {
        let (addr, program) = result?;
        let instructions = capstone
            .disasm_all(program, addr)
            .map_err(CapstoneError::new)?;
        for insn in instructions.iter() {
            let addr = insn.address();
            map.insert(addr, OwnedInsn::from(insn));
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

pub struct ElfInfo<'a> {
    pub elfbytes: ElfBytes<'a, AnyEndian>,
    pub symbol_map: BTreeMap<String, u64>,
    pub instruction_map: BTreeMap<u64, OwnedInsn<'a>>,
}

impl<'a> ElfInfo<'a> {
    pub fn new(elffile: &'a [u8]) -> Result<ElfInfo> {
        let elfbytes = ElfBytes::<AnyEndian>::minimal_parse(elffile)?;
        let symbol_map = create_symbolmap(&elfbytes)?;
        let instruction_map = create_instruction_map(&elfbytes)?;

        Ok(ElfInfo {
            elfbytes,
            symbol_map,
            instruction_map,
        })
    }

    pub fn segments(&self) -> impl Iterator<Item = Result<(u64, &[u8]), ParseError>> {
        iter_segments(&self.elfbytes)
    }
}

unsafe impl Send for ElfInfo<'_> {}
unsafe impl Sync for ElfInfo<'_> {}
