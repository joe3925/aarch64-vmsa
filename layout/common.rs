use crate::addr::PhysAddr;
use crate::format::{DescriptorFormat, DescriptorKind};
use crate::granule::{Level, TranslationGranule};

use super::{DescriptorError, DescriptorLayoutConfig};

pub fn require_leaf_kind(kind: DescriptorKind) -> Result<(), DescriptorError> {
    match kind {
        DescriptorKind::Block | DescriptorKind::Page => Ok(()),
        DescriptorKind::Table | DescriptorKind::Invalid => {
            Err(DescriptorError::InvalidDescriptorKindForLevel)
        }
    }
}

pub fn require_table_kind(kind: DescriptorKind) -> Result<(), DescriptorError> {
    if kind == DescriptorKind::Table {
        Ok(())
    } else {
        Err(DescriptorError::InvalidDescriptorKindForLevel)
    }
}

pub fn validate_config(
    config: DescriptorLayoutConfig,
    format_address_bits: u8,
) -> Result<(), DescriptorError> {
    if config.output_addr_bits == 0 || config.output_addr_bits > format_address_bits {
        Err(DescriptorError::InvalidFieldValue)
    } else {
        Ok(())
    }
}

pub fn validate_address_range(address: u64, output_addr_bits: u8) -> Result<(), DescriptorError> {
    if address & !lower_u64_bits_mask(output_addr_bits) != 0 {
        Err(DescriptorError::AddressOutOfRange)
    } else {
        Ok(())
    }
}

pub fn validate_address(
    address: u64,
    alignment_shift: u8,
    config: DescriptorLayoutConfig,
    format_address_bits: u8,
) -> Result<(), DescriptorError> {
    validate_config(config, format_address_bits)?;
    validate_address_range(address, config.output_addr_bits)?;
    if address & lower_u64_bits_mask(alignment_shift) != 0 {
        return Err(DescriptorError::AddressNotAligned);
    }
    Ok(())
}

pub fn encode_direct_address(
    address: PhysAddr,
    alignment_shift: u8,
    config: DescriptorLayoutConfig,
    format_address_bits: u8,
    address_field_mask: u128,
) -> Result<u128, DescriptorError> {
    validate_address(address.0, alignment_shift, config, format_address_bits)?;
    Ok(address.0 as u128 & address_field_mask)
}

pub fn decode_direct_output_address<F, G>(
    raw: u128,
    level: Level,
    config: DescriptorLayoutConfig,
    format_address_bits: u8,
    address_field_mask: u128,
    kind: DescriptorKind,
) -> Result<PhysAddr, DescriptorError>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    let shift = output_shift_for_kind::<F, G>(kind, level)?;
    validate_config(config, format_address_bits)?;
    let encoded = raw & address_field_mask;
    if encoded & lower_bits_mask(shift) != 0 {
        return Err(DescriptorError::AddressNotAligned);
    }

    let address = encoded as u64;
    validate_address_range(address, config.output_addr_bits)?;
    Ok(PhysAddr(address))
}

pub fn validate_raw_output_address<F, G>(
    raw: u128,
    level: Level,
    config: DescriptorLayoutConfig,
    format_address_bits: u8,
    address_field_mask: u128,
    kind: DescriptorKind,
) -> Result<(), DescriptorError>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    let shift = output_shift_for_kind::<F, G>(kind, level)?;
    validate_config(config, format_address_bits)?;
    let encoded = raw & address_field_mask;
    if encoded & lower_bits_mask(shift) != 0 {
        return Err(DescriptorError::AddressNotAligned);
    }
    validate_address_range(encoded as u64, config.output_addr_bits)
}

pub fn validate_raw_table_address(
    raw: u128,
    config: DescriptorLayoutConfig,
    format_address_bits: u8,
    address_field_mask: u128,
    alignment_shift: u8,
) -> Result<(), DescriptorError> {
    validate_config(config, format_address_bits)?;
    let encoded = raw & address_field_mask;
    if encoded & lower_bits_mask(alignment_shift) != 0 {
        return Err(DescriptorError::AddressNotAligned);
    }
    validate_address_range(encoded as u64, config.output_addr_bits)
}

pub fn output_shift_for_kind<F, G>(
    kind: DescriptorKind,
    level: Level,
) -> Result<u8, DescriptorError>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    match kind {
        DescriptorKind::Table | DescriptorKind::Page => Ok(G::SHIFT),
        DescriptorKind::Block => leaf_output_shift::<F, G>(level),
        DescriptorKind::Invalid => Err(DescriptorError::InvalidDescriptorKindForLevel),
    }
}

pub fn leaf_output_shift<F, G>(level: Level) -> Result<u8, DescriptorError>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    let delta = F::FINAL_LEVEL.as_i8() - level.as_i8();
    if delta < 0 {
        return Err(DescriptorError::InvalidDescriptorKindForLevel);
    }

    Ok(G::SHIFT + (G::SHIFT - F::DESCRIPTOR_SHIFT) * delta as u8)
}

pub const fn lower_bits_mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

pub const fn lower_u64_bits_mask(bits: u8) -> u64 {
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}
