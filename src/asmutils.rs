// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use capstone::{Capstone, OwnedInsn};

use unicorn_engine::Unicorn;

pub fn disassemble<'a, D>(
    emu: &Unicorn<D>,
    capstone: &Capstone,
    address: u64,
    size: usize,
) -> OwnedInsn<'a> {
    let mut mem = [0u8; 8];
    emu.mem_read(address, &mut mem[..size as usize]).unwrap();
    (&capstone
        .disasm_count(&mem[..size as usize], address, 1)
        .unwrap()[0])
        .into()
}
