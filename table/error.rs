use crate::addr::{PhysAddr, VirtAddr};

use super::TableAddressError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    EntryIndexOutOfRange { index: usize, entries: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    AddressOverflow,
    NullMapping,
    UnalignedTableAddress { addr: PhysAddr, align: u64 },
    RecursiveAddressUnavailable { table: PhysAddr },
    RecursiveLevelMismatch,
    RecursiveIndexOutOfRange { index: usize, entries: usize },
    InvalidRecursiveBase { base: VirtAddr },
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
