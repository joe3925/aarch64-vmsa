use crate::address::Level;
use crate::descriptor::DescriptorError;
use crate::table::{AccessError, TableAddressError, TableError};
use crate::translation::walk::{WalkCursorError, WalkInputAddr, WalkOutputAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapperError<AccessErrorKind, FrameErrorKind> {
    Access(AccessErrorKind),
    Frame(FrameErrorKind),
    AccessLocation(AccessError),
    Table(TableError),
    TableAddress(TableAddressError),
    Descriptor(DescriptorError),
    Cursor(WalkCursorError),

    InvalidRootLevel {
        root_level: Level,
        lowest_level: Level,
        final_level: Level,
    },
    InvalidRootAddressBits {
        addr_bits: u8,
        max_addr_bits: u8,
    },
    InvalidLeafLevel {
        level: Level,
        root_level: Level,
        final_level: Level,
    },
    InputAddressOutOfRange {
        addr: u64,
        addr_bits: u8,
    },
    AddressOverflow,
    InvalidLevel {
        level: Level,
    },
    WalkPathEntryNotTable {
        level: Level,
        entry_index: usize,
    },
    OutputAddressOverflow {
        base: WalkOutputAddr,
        offset: u64,
    },
    InvalidConfiguredOutputAddressBits {
        output_address_bits: u8,
        format_max_bits: u8,
    },
    OutputAddressOutOfRange {
        addr: WalkOutputAddr,
        output_address_bits: u8,
    },
    TableAddressOutOfRange {
        addr: u64,
        output_address_bits: u8,
    },

    UnalignedInput {
        addr: u64,
        align: u64,
    },
    UnalignedOutput {
        addr: WalkOutputAddr,
        align: u64,
    },
    InputNotLeafBase {
        input: WalkInputAddr,
        covered_input_base: u64,
        covered_size: u64,
        level: Level,
    },

    AlreadyMapped {
        input: WalkInputAddr,
        level: Level,
        entry_index: usize,
    },
    NotMapped {
        input: WalkInputAddr,
    },
}

impl<AccessErrorKind, FrameErrorKind> From<AccessError>
    for MapperError<AccessErrorKind, FrameErrorKind>
{
    fn from(error: AccessError) -> Self {
        Self::AccessLocation(error)
    }
}

impl<AccessErrorKind, FrameErrorKind> From<TableAddressError>
    for MapperError<AccessErrorKind, FrameErrorKind>
{
    fn from(error: TableAddressError) -> Self {
        Self::TableAddress(error)
    }
}

impl<AccessErrorKind, FrameErrorKind> From<TableError>
    for MapperError<AccessErrorKind, FrameErrorKind>
{
    fn from(error: TableError) -> Self {
        Self::Table(error)
    }
}

impl<AccessErrorKind, FrameErrorKind> From<DescriptorError>
    for MapperError<AccessErrorKind, FrameErrorKind>
{
    fn from(error: DescriptorError) -> Self {
        Self::Descriptor(error)
    }
}

impl<AccessErrorKind, FrameErrorKind> From<WalkCursorError>
    for MapperError<AccessErrorKind, FrameErrorKind>
{
    fn from(error: WalkCursorError) -> Self {
        Self::Cursor(error)
    }
}

pub(super) fn map_walk_error<AccessErrorKind, FrameErrorKind>(
    error: crate::translation::walk::WalkError<AccessErrorKind>,
) -> MapperError<AccessErrorKind, FrameErrorKind> {
    match error {
        crate::translation::walk::WalkError::Access(error) => MapperError::Access(error),
        crate::translation::walk::WalkError::AccessLocation(error) => {
            MapperError::AccessLocation(error)
        }
        crate::translation::walk::WalkError::Cursor(error) => MapperError::Cursor(error),
        crate::translation::walk::WalkError::InvalidTableAddress(error) => {
            MapperError::TableAddress(error)
        }
        crate::translation::walk::WalkError::EntryIndexOutOfRange { index, entries } => {
            MapperError::Table(TableError::EntryIndexOutOfRange { index, entries })
        }
        crate::translation::walk::WalkError::TableDescriptorAtFinalLevel { level } => {
            MapperError::InvalidLevel { level }
        }
        crate::translation::walk::WalkError::PathEntryNotTable { level, entry_index } => {
            MapperError::WalkPathEntryNotTable { level, entry_index }
        }
        crate::translation::walk::WalkError::OutputAddressOverflow { base, offset } => {
            MapperError::OutputAddressOverflow { base, offset }
        }
    }
}
