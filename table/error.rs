use crate::address::Level;
use crate::address::{PhysAddr, VirtAddr};

use super::TableAddressError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    EntryIndexOutOfRange { index: usize, entries: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    AddressOverflow,
    NullMapping,
    UnalignedTableAddress {
        addr: PhysAddr,
        align: u64,
    },
    RecursiveLevelMismatch,
    RecursiveIndexOutOfRange {
        index: usize,
        entries: usize,
    },
    InvalidRecursiveBase {
        base: VirtAddr,
    },
    InvalidTableLevel {
        root_level: Level,
        level: Level,
        final_level: Level,
    },
    TablePathLengthMismatch {
        expected: u8,
        actual: u8,
    },
    TablePathTerminalLevelMismatch {
        expected: Level,
        actual: Level,
    },
    TablePathIndexOutOfRange {
        index: usize,
        entries: usize,
    },
    TablePathCapacityExceeded {
        len: u8,
        index_bits: u8,
    },
    TablePathStrideCapacityExceeded {
        len: u8,
        stride_bits: u8,
    },
    TableAllocationLayoutOverflow {
        entries: usize,
        descriptor_bytes: usize,
    },
    InvalidTableTransition {
        parent_level: Level,
        child_level: Level,
        stride_count: u8,
    },
    InvalidTableLevelStep {
        step: u8,
    },
    InvalidTableStrideCount {
        stride_count: u8,
    },
    TablePathLevelUnavailable {
        root_level: Level,
        level: Level,
        len: u8,
    },
}

impl From<TableAddressError> for AccessError {
    fn from(error: TableAddressError) -> Self {
        match error {
            TableAddressError::Unaligned { addr, align } => {
                Self::UnalignedTableAddress { addr, align }
            }
        }
    }
}
