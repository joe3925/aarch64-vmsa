use core::marker::PhantomData;

use crate::format::DescriptorFormat;
use crate::granule::{Level, TranslationGranule};

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

    pub const fn level_shift(level: Level) -> u8 {
        let delta = F::FINAL_LEVEL.as_i8() - level.as_i8();

        G::SHIFT + Self::index_bits() * delta as u8
    }

    pub const fn index_at_level_raw(input: u64, level: Level) -> usize {
        ((input >> Self::level_shift(level)) & Self::index_mask()) as usize
    }
}
