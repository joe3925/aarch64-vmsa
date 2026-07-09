use core::marker::PhantomData;

use crate::address::{Level, TranslationGranule};
use crate::descriptor::DescriptorFormat;

pub struct TableGeometry<F, G>(PhantomData<(F, G)>);

impl<F, G> TableGeometry<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn entries() -> usize {
        (G::SIZE as usize) / F::DESCRIPTOR_BYTES
    }

    pub const fn index_bits() -> u8 {
        G::SHIFT - F::DESCRIPTOR_SHIFT
    }

    pub const fn index_mask() -> u64 {
        (1u64 << Self::index_bits()) - 1
    }

    pub const fn checked_level_shift(level: Level) -> Option<u8> {
        if level.is_after(F::FINAL_LEVEL) {
            return None;
        }

        let delta = F::FINAL_LEVEL.as_i8() - level.as_i8();

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

    pub const fn level_shift(level: Level) -> u8 {
        match Self::checked_level_shift(level) {
            Some(shift) => shift,
            None => panic!("invalid table level shift"),
        }
    }

    pub const fn index_at_level_raw(input: u64, level: Level) -> Option<usize> {
        match Self::checked_level_shift(level) {
            Some(shift) => Some(((input >> shift) & Self::index_mask()) as usize),
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
