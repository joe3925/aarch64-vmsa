use crate::address::{Level, PhysAddr};
use crate::attrs::AttrError;
use crate::descriptor::DescriptorError;
use crate::table::{AccessError, TableAddressError, TableError};
use crate::walkers::{WalkCursorError, WalkInputAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapperError<AccessErrorKind, FrameErrorKind> {
    Access(AccessErrorKind),
    Frame(FrameErrorKind),
    AccessLocation(AccessError),
    Table(TableError),
    TableAddress(TableAddressError),
    Descriptor(DescriptorError),
    Attr(AttrError),
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
    OutputAddressOverflow {
        base: PhysAddr,
        offset: u64,
    },
    OutputAddressOutOfRange {
        addr: PhysAddr,
        output_address_bits: u8,
    },

    UnalignedInput {
        addr: u64,
        align: u64,
    },
    UnalignedOutput {
        addr: PhysAddr,
        align: u64,
    },
    LengthNotMappingMultiple {
        len: u64,
        mapping_size: u64,
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

impl<AccessErrorKind, FrameErrorKind> From<AttrError>
    for MapperError<AccessErrorKind, FrameErrorKind>
{
    fn from(error: AttrError) -> Self {
        Self::Attr(error)
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
    error: crate::walkers::WalkError<AccessErrorKind>,
) -> MapperError<AccessErrorKind, FrameErrorKind> {
    match error {
        crate::walkers::WalkError::Access(error) => MapperError::Access(error),
        crate::walkers::WalkError::AccessLocation(error) => MapperError::AccessLocation(error),
        crate::walkers::WalkError::Cursor(error) => MapperError::Cursor(error),
        crate::walkers::WalkError::InvalidTableAddress(error) => MapperError::TableAddress(error),
        crate::walkers::WalkError::EntryIndexOutOfRange { index, entries } => {
            MapperError::Table(TableError::EntryIndexOutOfRange { index, entries })
        }
        crate::walkers::WalkError::TableDescriptorAtFinalLevel { level } => {
            MapperError::InvalidLevel { level }
        }
        crate::walkers::WalkError::OutputAddressOverflow { base, offset } => {
            MapperError::OutputAddressOverflow { base, offset }
        }
    }
}
