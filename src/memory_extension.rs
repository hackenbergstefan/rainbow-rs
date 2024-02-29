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

pub struct CacheLruWriteThrough {
    bus_size: usize,
    bus: [u8; MAX_BUS_SIZE],
    cache_lines: usize,
    cache: ArrayVec<(u64, [u8; MAX_BUS_SIZE]), MAX_CACHE_LINES>,
}

impl CacheLruWriteThrough {
    pub fn new(bus_size: usize, cache_lines: usize) -> Self {
        Self {
            bus_size,
            bus: [0; MAX_BUS_SIZE],
            cache_lines,
            cache: ArrayVec::new(),
        }
    }

    /// Update bus. Leaks: Bus
    fn update_and_leak_bus(&mut self, scadata: &mut ScaData, newvalue: [u8; MAX_BUS_SIZE]) {
        scadata.bus_updates.push((self.bus, newvalue));
        self.bus = newvalue;
    }

    /// Update cache line with new content.
    /// Leaks: Cache (may), Bus[write] (may), Memory (may)
    fn update_and_leak_cache_bus_memory(
        &mut self,
        scadata: &mut ScaData,
        index: usize,
        newcontent: [u8; MAX_BUS_SIZE],
    ) {
        let line = &self.cache[index];
        if line.1 == newcontent {
            return;
        }
        let (address, oldcontent) = self.cache.pop_at(index).unwrap();

        scadata.cache_updates.push((oldcontent, newcontent));
        scadata.bus_updates.push((oldcontent, newcontent));
        scadata.memory_updates.push((oldcontent, newcontent));
        self.cache.push((address, newcontent));
    }
}

/// Least Recently Used (LRU) cache implementation with write-through (https://stackoverflow.com/a/27161893).
/// On a memory update the cache behaves as follows:
/// 1. If the address is in the cache, the cache line is updated (and moved to end)
///    and the bus and memory are updated if necessary.
/// 2. If the address is not in the cache, the last cache line is removed if necessary,
///    the new cache line is added and the bus and memory are updated if necessary.
impl MemoryExtension for CacheLruWriteThrough {
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
            self.update_and_leak_cache_bus_memory(scadata, index, memory_after);
        } else {
            // 1. Read new memory. Leaks: Bus[read]
            self.update_and_leak_bus(scadata, memory_before);

            // 2. Update cache. Leaks: Cache
            let oldline_content = {
                if self.cache.len() == self.cache_lines {
                    // 2a. Remove last cache line
                    let (_, oldline_content) = self.cache.pop_at(0).unwrap();
                    oldline_content
                } else {
                    // 2b. Add new line
                    [0; MAX_BUS_SIZE]
                }
            };
            scadata.cache_updates.push((oldline_content, memory_before));
            self.cache.push((address, memory_before));

            // 3. Update cache line and bus if necessary. Leaks: Cache (may), Bus (may), Memory (may)
            self.update_and_leak_cache_bus_memory(scadata, self.cache.len() - 1, memory_after);
        }
        trace!("Cache: {:x?}", self.cache);
    }
}

#[derive(Debug)]
struct CacheLruWriteBackCacheLine {
    address: u64,
    content: [u8; MAX_BUS_SIZE],
    memory: [u8; MAX_BUS_SIZE],
}

pub struct CacheLruWriteBack {
    bus_size: usize,
    bus: [u8; MAX_BUS_SIZE],
    cache_lines: usize,
    cache: ArrayVec<CacheLruWriteBackCacheLine, MAX_CACHE_LINES>,
}

impl CacheLruWriteBack {
    pub fn new(bus_size: usize, cache_lines: usize) -> Self {
        Self {
            bus_size,
            bus: [0; MAX_BUS_SIZE],
            cache_lines,
            cache: ArrayVec::new(),
        }
    }

    /// Update bus. Leaks: Bus
    fn update_and_leak_bus(&mut self, scadata: &mut ScaData, newvalue: [u8; MAX_BUS_SIZE]) {
        scadata.bus_updates.push((self.bus, newvalue));
        self.bus = newvalue;
    }

    /// Update cache line with new content.
    /// Leaks: Cache (may)
    fn update_and_leak_cache(
        &mut self,
        scadata: &mut ScaData,
        index: usize,
        newcontent: [u8; MAX_BUS_SIZE],
    ) {
        let line = &self.cache[index];
        if line.content == newcontent {
            return;
        }

        scadata.cache_updates.push((line.content, newcontent));
        let newline = CacheLruWriteBackCacheLine {
            address: line.address,
            content: newcontent,
            memory: line.memory,
        };
        self.cache.remove(index);
        self.cache.push(newline);
    }

    /// Execute write-back:
    /// 1. Pop lru cache line
    /// 2. If line is dirty, leak bus and memory
    fn write_back_and_leak(&mut self, scadata: &mut ScaData) -> CacheLruWriteBackCacheLine {
        let oldline = self.cache.pop_at(0).unwrap();
        if oldline.content != oldline.memory {
            self.update_and_leak_bus(scadata, oldline.content);
            scadata
                .memory_updates
                .push((oldline.memory, oldline.content));
        }
        oldline
    }
}

/// Least Recently Used (LRU) cache implementation with write-through (https://stackoverflow.com/a/27161893).
/// The memory is modelled as read-modify-write independently of actual content changes.
/// On an update the cache behaves as follows:
/// 1. If the address is in the cache, the cache line is updated (and moved to end).
/// 2. If the address is not in the cache, the last cache line is removed if necessary,
///    the new cache line is added and updated if necessary.
/// 3. If the line pops out of the cache and it is written back to bus and memory if necessary.
impl MemoryExtension for CacheLruWriteBack {
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
        if let Some(index) = self.cache.iter().position(|line| line.address == address) {
            let line = &self.cache[index];
            assert!(
                line.content == memory_before,
                "Cache line {index} at {address:08x} is not up to date: {:x?} != {:x?}",
                line.content,
                memory_before
            );

            // Update cache line. Leaks: cache (may)
            self.update_and_leak_cache(scadata, index, memory_after);
        } else {
            let oldline_content = {
                // 1a. Remove lru cache line. Leaks: cache, bus[write] (may), memory (may)
                if self.cache.len() == self.cache_lines {
                    let oldline = self.write_back_and_leak(scadata);
                    oldline.content
                // 1b. Leaks: cache
                } else {
                    [0; MAX_BUS_SIZE]
                }
            };

            // 2. "Read" from memory. Leaks: bus[read] and add new cache line
            self.update_and_leak_bus(scadata, memory_before);

            // 3. Add new cache line. Leaks: Cache
            scadata.cache_updates.push((oldline_content, memory_before));
            self.cache.push(CacheLruWriteBackCacheLine {
                address,
                content: memory_before,
                memory: memory_before,
            });

            // 4. Update cache line if necessary. Leaks: Cache (may)
            self.update_and_leak_cache(scadata, self.cache.len() - 1, memory_after);
        }
        trace!("Cache: {:x?}", self.cache);
    }
}
