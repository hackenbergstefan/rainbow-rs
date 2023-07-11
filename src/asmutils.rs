// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;

use capstone::prelude::BuildsCapstone;
use capstone::Capstone;
use capstone::OwnedInsn;

use elf::{endian::AnyEndian, ElfBytes};
use unicorn_engine::Unicorn;

pub fn disassemble<'a, D>(
    emu: &Unicorn<D>,
    capstone: &Capstone,
    address: u64,
    size: usize,
) -> OwnedInsn<'a> {
    let mut mem = [0u8; 8];
    emu.mem_read(address, &mut mem[..size]).unwrap();
    (&capstone.disasm_count(&mem[..size], address, 1).unwrap()[0]).into()
}

fn iter_segments<'a>(elfbytes: &'a ElfBytes<AnyEndian>) -> impl Iterator<Item = (u64, &'a [u8])> {
    elfbytes
        .segments()
        .unwrap()
        .into_iter()
        .map(|header| (header.p_paddr, elfbytes.segment_data(&header).unwrap()))
}

fn create_instruction_map<'a>(elfbytes: &ElfBytes<AnyEndian>) -> BTreeMap<u64, OwnedInsn<'a>> {
    let mut map = BTreeMap::new();

    let capstone = Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()
        .unwrap();

    for (addr, program) in iter_segments(elfbytes) {
        let instructions = capstone.disasm_all(program, addr).unwrap();
        for insn in instructions.iter() {
            let addr = insn.address();
            // let detail = capstone.insn_detail(insn).unwrap();
            map.insert(addr, OwnedInsn::from(insn));
        }
    }
    map
}

fn create_symbolmap(elfbytes: &ElfBytes<AnyEndian>) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    let (symtable, strtable) = elfbytes.symbol_table().unwrap().unwrap();
    for symbol in symtable {
        map.insert(
            strtable.get(symbol.st_name as usize).unwrap().to_owned(),
            symbol.st_value,
        );
    }
    map
}

pub struct ElfInfo<'a> {
    pub elfbytes: ElfBytes<'a, AnyEndian>,
    pub symbol_map: BTreeMap<String, u64>,
    pub instruction_map: BTreeMap<u64, OwnedInsn<'a>>,
}

impl<'a> ElfInfo<'a> {
    pub fn new(elffile: &'a [u8]) -> ElfInfo {
        let elfbytes = ElfBytes::<AnyEndian>::minimal_parse(elffile).unwrap();
        let symbol_map = create_symbolmap(&elfbytes);
        let instruction_map = create_instruction_map(&elfbytes);

        ElfInfo {
            elfbytes,
            symbol_map,
            instruction_map,
        }
    }

    pub fn segments(&self) -> impl Iterator<Item = (u64, &[u8])> {
        iter_segments(&self.elfbytes)
    }
}

unsafe impl Send for ElfInfo<'_> {}
