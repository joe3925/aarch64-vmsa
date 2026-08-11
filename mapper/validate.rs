use crate::address::{Level, PhysAddr};
use crate::descriptor::DescriptorFormat;
use crate::translation::walk::WalkLeafKind;

use super::MapperError;

pub(super) fn require_input_addr<AccessErrorKind, FrameErrorKind>(
    addr: u64,
    addr_bits: u8,
) -> Result<(), MapperError<AccessErrorKind, FrameErrorKind>> {
    if addr_bits >= 64 {
        return Ok(());
    }

    if addr >> addr_bits != 0 {
        Err(MapperError::InputAddressOutOfRange { addr, addr_bits })
    } else {
        Ok(())
    }
}

pub(super) fn require_aligned_input<AccessErrorKind, FrameErrorKind>(
    addr: u64,
    align: u64,
) -> Result<(), MapperError<AccessErrorKind, FrameErrorKind>> {
    if addr & (align - 1) == 0 {
        Ok(())
    } else {
        Err(MapperError::UnalignedInput { addr, align })
    }
}

pub(super) fn require_aligned_output<AccessErrorKind, FrameErrorKind>(
    addr: PhysAddr,
    align: u64,
) -> Result<(), MapperError<AccessErrorKind, FrameErrorKind>> {
    if addr.0 & (align - 1) == 0 {
        Ok(())
    } else {
        Err(MapperError::UnalignedOutput { addr, align })
    }
}

pub(super) fn require_output_range<AccessErrorKind, FrameErrorKind>(
    base: PhysAddr,
    len: u64,
    output_address_bits: u8,
) -> Result<(), MapperError<AccessErrorKind, FrameErrorKind>> {
    if len == 0 {
        return Ok(());
    }

    let offset = len - 1;

    base.0
        .checked_add(offset)
        .ok_or(MapperError::OutputAddressOverflow { base, offset })?;

    require_output_address::<AccessErrorKind, FrameErrorKind>(base, output_address_bits)?;
    require_output_address::<AccessErrorKind, FrameErrorKind>(
        PhysAddr(base.0 + offset),
        output_address_bits,
    )?;

    Ok(())
}

pub(super) fn require_output_address<AccessErrorKind, FrameErrorKind>(
    addr: PhysAddr,
    output_address_bits: u8,
) -> Result<(), MapperError<AccessErrorKind, FrameErrorKind>> {
    if output_address_bits >= 64 || addr.0 >> output_address_bits == 0 {
        Ok(())
    } else {
        Err(MapperError::OutputAddressOutOfRange {
            addr,
            output_address_bits,
        })
    }
}

pub(super) fn require_table_address<AccessErrorKind, FrameErrorKind>(
    addr: u64,
    output_address_bits: u8,
) -> Result<(), MapperError<AccessErrorKind, FrameErrorKind>> {
    if output_address_bits >= 64 || addr >> output_address_bits == 0 {
        Ok(())
    } else {
        Err(MapperError::TableAddressOutOfRange {
            addr,
            output_address_bits,
        })
    }
}

pub(super) fn leaf_kind<F>(level: Level) -> WalkLeafKind
where
    F: DescriptorFormat,
{
    if level == F::FINAL_LEVEL {
        WalkLeafKind::Page
    } else {
        WalkLeafKind::Block
    }
}
