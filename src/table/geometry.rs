use core::marker::PhantomData;

use crate::address::{Level, TranslationGranule};
use crate::descriptor::DescriptorFormat;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TableGeometry<F, G>(PhantomData<(F, G)>);

impl<F, G> TableGeometry<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    /// This function makes a stateless geometry value for the specified format and granule.
    pub const fn new() -> Self {
        Self(PhantomData)
    }

    /// This function returns a supported root level for `addr_bits`.
    /// It selects the level with the minimum number of table-walk steps.
    ///
    /// For `addr_bits == 0`, this function returns `F::FINAL_LEVEL`.
    /// For an address width greater than the maximum, it returns
    /// `F::EXTENDED_LOWEST_ROOT_LEVEL`.
    /// Root validation rejects these address widths.
    pub const fn root_level_for_addr_bits(addr_bits: u8) -> Level {
        let mut level = F::FINAL_LEVEL;

        loop {
            match Self::max_addr_bits(level) {
                Some(max_addr_bits) if addr_bits <= max_addr_bits => return level,
                _ => {}
            }

            if !F::EXTENDED_LOWEST_ROOT_LEVEL.is_before(level) {
                return level;
            }

            level = level.previous();
        }
    }

    /// This function returns the maximum input-address width for a root at `level`.
    pub const fn max_addr_bits(level: Level) -> Option<u8> {
        if level.is_before(F::EXTENDED_LOWEST_ROOT_LEVEL) || level.is_after(F::FINAL_LEVEL) {
            return None;
        }

        let delta = F::FINAL_LEVEL.as_i8() as i16 - level.as_i8() as i16;
        if delta < 0 {
            return None;
        }

        let bits = G::SHIFT as u16 + Self::index_bits() as u16 * (delta as u16 + 1);
        Some(if bits > u64::BITS as u16 {
            u64::BITS as u8
        } else {
            bits as u8
        })
    }

    pub const fn entries() -> usize {
        (G::SIZE as usize) / F::DESCRIPTOR_BYTES
    }

    pub const fn checked_entries_for_stride_count(stride_count: u8) -> Option<usize> {
        if stride_count == 0 {
            return None;
        }

        let bits = Self::index_bits() as u16 * stride_count as u16;
        if bits >= usize::BITS as u16 {
            return None;
        }

        Some(1usize << bits)
    }

    pub const fn entries_for_stride_count(stride_count: u8) -> usize {
        match Self::checked_entries_for_stride_count(stride_count) {
            Some(entries) => entries,
            None => panic!("invalid table stride count"),
        }
    }

    pub const fn index_bits() -> u8 {
        G::SHIFT - F::DESCRIPTOR_SHIFT
    }

    pub const fn index_mask() -> u64 {
        (1u64 << Self::index_bits()) - 1
    }

    pub const fn checked_index_mask_for_stride_count(stride_count: u8) -> Option<u64> {
        if stride_count == 0 {
            return None;
        }

        let bits = Self::index_bits() as u16 * stride_count as u16;
        if bits >= u64::BITS as u16 {
            return None;
        }

        Some((1u64 << bits) - 1)
    }

    pub const fn index_mask_for_stride_count(stride_count: u8) -> u64 {
        match Self::checked_index_mask_for_stride_count(stride_count) {
            Some(mask) => mask,
            None => panic!("invalid table stride count"),
        }
    }

    pub const fn checked_level_shift(level: Level) -> Option<u8> {
        if level.is_before(F::EXTENDED_LOWEST_ROOT_LEVEL) || level.is_after(F::FINAL_LEVEL) {
            return None;
        }

        let delta = F::FINAL_LEVEL.as_i8() as i16 - level.as_i8() as i16;

        if delta < 0 {
            return None;
        }

        let index_bits = Self::index_bits() as u16;
        let shift = G::SHIFT as u16 + index_bits * delta as u16;

        if shift >= u64::BITS as u16 {
            return None;
        }

        Some(shift as u8)
    }

    /// This function returns the input-address span for one entry at `level`.
    ///
    /// This span gives only table-geometry information.
    /// It does not identify a supported leaf level.
    pub const fn level_span(level: Level) -> Option<u64> {
        match Self::checked_level_shift(level) {
            Some(shift) => Some(1u64 << shift),
            None => None,
        }
    }

    pub const fn level_shift(level: Level) -> u8 {
        match Self::checked_level_shift(level) {
            Some(shift) => shift,
            None => panic!("invalid table level shift"),
        }
    }

    pub const fn index_at_level_raw(input: u64, level: Level) -> Option<usize> {
        Self::index_at_level_raw_strides(input, level, 1)
    }

    pub const fn index_at_level_raw_strides(
        input: u64,
        level: Level,
        stride_count: u8,
    ) -> Option<usize> {
        match Self::checked_level_shift(level) {
            Some(shift) => match Self::checked_index_mask_for_stride_count(stride_count) {
                Some(mask) => Some(((input >> shift) & mask) as usize),
                None => None,
            },
            None => None,
        }
    }

    pub const fn offset_at_level_raw(input: u64, level: Level) -> Option<u64> {
        match Self::checked_level_shift(level) {
            Some(shift) => Some(input & ((1u64 << shift) - 1)),
            None => None,
        }
    }
}
