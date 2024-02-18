// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

//! Implementation of different memory extensions.

use arrayvec::ArrayVec;
use log::trace;
use unicorn_engine::unicorn_const::MemType;

use crate::ScaData;

/// Maximum bus size in bytes.
pub const MAX_BUS_SIZE: usize = 16;

/// Maximum cache size in bytes.
pub const MAX_CACHE_SIZE: usize = 1024;

/// Maximum cache lines.
pub const MAX_CACHE_LINES: usize = MAX_CACHE_SIZE / MAX_BUS_SIZE;

pub trait MemoryExtension {
    fn bus_size(&self) -> usize;

    fn reset(&mut self);

    fn update(
        &mut self,
        scadata: &mut ScaData,
        memtype: MemType,
        address: u64,
        memory_before: [u8; MAX_BUS_SIZE],
        memory_after: [u8; MAX_BUS_SIZE],
    );
}

#[derive(Default)]
pub struct NoBusNoCache;

impl NoBusNoCache {
    pub fn new() -> Self {
        Self {}
    }
}

impl MemoryExtension for NoBusNoCache {
    #[inline]
    fn bus_size(&self) -> usize {
        0
    }

    fn reset(&mut self) {}

    fn update(
        &mut self,
        scadata: &mut ScaData,
        _memtype: MemType,
        _address: u64,
        memory_before: [u8; MAX_BUS_SIZE],
        memory_after: [u8; MAX_BUS_SIZE],
    ) {
        scadata.memory_updates.push((memory_before, memory_after));
    }
}

#[derive(Default)]
pub struct BusNoCache {
    bus_size: usize,
    bus: [u8; MAX_BUS_SIZE],
}

impl BusNoCache {
    pub fn new(bus_size: usize) -> Self {
        Self {
            bus_size,
            bus: [0; MAX_BUS_SIZE],
        }
    }
}

impl MemoryExtension for BusNoCache {
    #[inline]
    fn bus_size(&self) -> usize {
        self.bus_size
    }

    fn reset(&mut self) {}

    fn update(
        &mut self,
        scadata: &mut ScaData,
        _memtype: MemType,
        _address: u64,
        memory_before: [u8; MAX_BUS_SIZE],
        memory_after: [u8; MAX_BUS_SIZE],
    ) {
        // Load data from memory to bus
        if self.bus != memory_before {
            scadata.bus_updates.push((self.bus, memory_before));
            self.bus = memory_before;
        }

        // Store updated data from cpu to bus
        if self.bus != memory_after {
            scadata.bus_updates.push((self.bus, memory_after));
            self.bus = memory_after;
        }

        // Update memory
        if memory_before != memory_after {
            scadata.memory_updates.push((memory_before, memory_after));
        }
    }
}

pub struct CacheLru {
    bus_size: usize,
    bus: [u8; MAX_BUS_SIZE],
    cache_lines: usize,
    cache: ArrayVec<(u64, [u8; MAX_BUS_SIZE]), MAX_CACHE_LINES>,
}

impl CacheLru {
    pub fn new(bus_size: usize, cache_lines: usize) -> Self {
        Self {
            bus_size,
            bus: [0; MAX_BUS_SIZE],
            cache_lines,
            cache: ArrayVec::new(),
        }
    }
}

/// Least Recently Used (LRU) cache implementation.
/// On a memory update the cache behaves as follows:
/// 1. If the address is in the cache, the cache line is updated (and moved to end)
///    and the bus is updated if necessary.
/// 2. If the address is not in the cache, the last cache line is removed if necessary,
///    the new cache line is added and the bus is updated if necessary.
impl MemoryExtension for CacheLru {
    #[inline]
    fn bus_size(&self) -> usize {
        self.bus_size
    }

    fn reset(&mut self) {
        self.cache.clear();
        self.bus = [0; MAX_BUS_SIZE];
    }

    fn update(
        &mut self,
        scadata: &mut ScaData,
        _memtype: MemType,
        address: u64,
        memory_before: [u8; MAX_BUS_SIZE],
        memory_after: [u8; MAX_BUS_SIZE],
    ) {
        assert!((address as usize % self.bus_size) == 0);
        // Check if address is in cache
        if let Some(index) = self.cache.iter().position(|(addr, _)| *addr == address) {
            assert!(
                self.cache[index].1 == memory_before,
                "Cache line {index} at {address:08x} is not up to date: {:x?} != {:x?}",
                self.cache[index].1,
                memory_before
            );

            // Update cache line and bus if necessary
            if memory_before != memory_after {
                scadata
                    .cache_updates
                    .push((self.cache[index].1, memory_after));
                self.cache.remove(index);
                self.cache.push((address, memory_after));
                scadata.bus_updates.push((self.bus, memory_after));
                self.bus = memory_after;
            }
        } else {
            // Remove last cache line if necessary
            if self.cache.len() == self.cache_lines {
                scadata.cache_updates.push((self.cache[0].1, memory_before));
                self.cache.remove(0);
            } else {
                scadata
                    .cache_updates
                    .push(([0; MAX_BUS_SIZE], memory_before));
            }
            self.cache.push((address, memory_before));

            // Update cache line and bus if necessary
            if memory_before != memory_after {
                let last = self.cache.last_mut().unwrap();
                scadata.cache_updates.push((last.1, memory_after));
                last.1 = memory_after;
                scadata.bus_updates.push((self.bus, memory_after));
                self.bus = memory_after;
            }
        }
        trace!("Cache: {:x?}", self.cache);

        // Update memory
        if memory_before != memory_after {
            scadata.memory_updates.push((memory_before, memory_after));
        }
    }
}
