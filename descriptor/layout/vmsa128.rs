use core::marker::PhantomData;

use crate::address::PhysAddr;
use crate::address::{GranuleKind, Level, TranslationGranule};
use crate::descriptor::{DescriptorKind, HasLayout, Vmsa128};
use crate::descriptor::{
    Vmsa128Stage1LeafFields, Vmsa128Stage1TableFields, Vmsa128Stage2LeafFields,
    Vmsa128Stage2TableFields,
};
use crate::table::TableTransition;
use crate::translation::{Stage1, Stage2};

use super::{DescriptorError, DescriptorLayout, NextTableDescriptor, RawFieldBlock};

const VMSA128_VALID: u128 = 1 << 0;
const VMSA128_ADDR_FIELD_MASK: u128 = 0x00FF_FFFF_FFFF_F000;

const VMSA128_FIELD_LO_SHIFT: u8 = 2;
const VMSA128_TABLE_LO_SHIFT: u8 = 4;
const VMSA128_FIELD_HI_SHIFT: u8 = 108;

const VMSA128_SKL_SHIFT: u8 = 109;
const VMSA128_SKL_MASK: u128 = 0b11 << VMSA128_SKL_SHIFT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128Layout<S, G>(PhantomData<(S, G)>);

impl<G: TranslationGranule> HasLayout<Stage1, G> for Vmsa128 {
    type Layout = Vmsa128Layout<Stage1, G>;
}

impl<G: TranslationGranule> HasLayout<Stage2, G> for Vmsa128 {
    type Layout = Vmsa128Layout<Stage2, G>;
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa128, Stage1, G> for Vmsa128Layout<Stage1, G> {
    type LeafFields = Vmsa128Stage1LeafFields;
    type TableFields = Vmsa128Stage1TableFields;

    const ADDRESS_FIELD_MASK: u128 = VMSA128_ADDR_FIELD_MASK;

    fn kind(raw: u128, level: Level) -> DescriptorKind {
        vmsa128_kind(G::KIND, raw, level)
    }

    fn decode_leaf_fields(raw: u128, level: Level) -> Self::LeafFields {
        let (low, high) = decode_vmsa128_leaf_blocks(raw, level);
        Vmsa128Stage1LeafFields { low, high }
    }

    fn decode_table_fields(raw: u128, level: Level) -> Self::TableFields {
        let (low, high) = decode_vmsa128_table_blocks(raw, level);
        Vmsa128Stage1TableFields { low, high }
    }

    fn leaf_descriptor(output_pa: PhysAddr, level: Level, fields: Self::LeafFields) -> u128 {
        encode_vmsa128_leaf_blocks(output_pa, level, fields.low, fields.high)
    }

    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<Vmsa128, G>,
        fields: Self::TableFields,
    ) -> Result<u128, DescriptorError> {
        let high = table_high_with_transition_skl::<G>(transition, fields.high)?;
        Ok(encode_vmsa128_table_blocks(table_pa, fields.low, high))
    }

    fn output_address(raw: u128, level: Level) -> PhysAddr {
        decode_vmsa128_output_address::<G>(raw, level)
    }

    fn table_address(raw: u128, level: Level) -> PhysAddr {
        decode_vmsa128_table_address::<G>(raw, level)
    }

    fn next_table(raw: u128, level: Level) -> Option<NextTableDescriptor> {
        Some(NextTableDescriptor {
            address: decode_vmsa128_table_address::<G>(raw, level),
            level: next_vmsa128_table_level(raw, level)?,
            stride_count: vmsa128_raw_skl(raw) + 1,
        })
    }

    fn supports_table_transition(transition: TableTransition<Vmsa128, G>) -> bool {
        vmsa128_transition_skl::<G>(transition).is_some()
    }
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa128, Stage2, G> for Vmsa128Layout<Stage2, G> {
    type LeafFields = Vmsa128Stage2LeafFields;
    type TableFields = Vmsa128Stage2TableFields;

    const ADDRESS_FIELD_MASK: u128 = VMSA128_ADDR_FIELD_MASK;

    fn kind(raw: u128, level: Level) -> DescriptorKind {
        vmsa128_kind(G::KIND, raw, level)
    }

    fn decode_leaf_fields(raw: u128, level: Level) -> Self::LeafFields {
        let (low, high) = decode_vmsa128_leaf_blocks(raw, level);
        Vmsa128Stage2LeafFields { low, high }
    }

    fn decode_table_fields(raw: u128, level: Level) -> Self::TableFields {
        let (low, high) = decode_vmsa128_table_blocks(raw, level);
        Vmsa128Stage2TableFields { low, high }
    }

    fn leaf_descriptor(output_pa: PhysAddr, level: Level, fields: Self::LeafFields) -> u128 {
        encode_vmsa128_leaf_blocks(output_pa, level, fields.low, fields.high)
    }

    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<Vmsa128, G>,
        fields: Self::TableFields,
    ) -> Result<u128, DescriptorError> {
        let high = table_high_with_transition_skl::<G>(transition, fields.high)?;
        Ok(encode_vmsa128_table_blocks(table_pa, fields.low, high))
    }

    fn output_address(raw: u128, level: Level) -> PhysAddr {
        decode_vmsa128_output_address::<G>(raw, level)
    }

    fn table_address(raw: u128, level: Level) -> PhysAddr {
        decode_vmsa128_table_address::<G>(raw, level)
    }

    fn next_table(raw: u128, level: Level) -> Option<NextTableDescriptor> {
        Some(NextTableDescriptor {
            address: decode_vmsa128_table_address::<G>(raw, level),
            level: next_vmsa128_table_level(raw, level)?,
            stride_count: vmsa128_raw_skl(raw) + 1,
        })
    }

    fn supports_table_transition(transition: TableTransition<Vmsa128, G>) -> bool {
        vmsa128_transition_skl::<G>(transition).is_some()
    }
}

pub fn vmsa128_supports_leaf_level(granule: GranuleKind, level: Level) -> bool {
    let skip = Level::L3.as_i8() - level.as_i8();
    (0..=3).contains(&skip) && vmsa128_skl_supported(granule, skip as u8)
}

pub fn vmsa128_skl_supported(granule: GranuleKind, skl: u8) -> bool {
    !matches!(
        (granule, skl),
        (GranuleKind::Size16KiB | GranuleKind::Size64KiB, 3)
    )
}

fn vmsa128_transition_skl<G: TranslationGranule>(
    transition: TableTransition<Vmsa128, G>,
) -> Option<u8> {
    let level_step = transition.level_step();
    if level_step == 0 || transition.child().stride_count().raw() != level_step {
        return None;
    }

    let skl = level_step - 1;
    vmsa128_skl_supported(G::KIND, skl).then_some(skl)
}

fn table_high_with_transition_skl<G: TranslationGranule>(
    transition: TableTransition<Vmsa128, G>,
    high: RawFieldBlock<20>,
) -> Result<RawFieldBlock<20>, DescriptorError> {
    let Some(skl) = vmsa128_transition_skl::<G>(transition) else {
        return Err(DescriptorError::InvalidTableTransition {
            parent_level: transition.parent_level(),
            child_level: transition.child_level(),
            stride_count: transition.child().stride_count().raw(),
        });
    };

    Ok(raw_block(
        (high.bits() & !(0b11 << 1)) | (u128::from(skl) << 1),
    ))
}

fn vmsa128_kind(granule: GranuleKind, raw: u128, level: Level) -> DescriptorKind {
    if raw & VMSA128_VALID == 0 {
        return DescriptorKind::Invalid;
    }

    let skl = ((raw & VMSA128_SKL_MASK) >> VMSA128_SKL_SHIFT) as i8;
    if !vmsa128_skl_supported(granule, skl as u8) {
        return DescriptorKind::Invalid;
    }

    let sum = level.as_i8() + skl;

    if sum < Level::L3.as_i8() {
        DescriptorKind::Table
    } else if sum == Level::L3.as_i8() {
        if level == Level::L3 {
            DescriptorKind::Page
        } else {
            DescriptorKind::Block
        }
    } else {
        DescriptorKind::Invalid
    }
}

fn vmsa128_raw_skl(raw: u128) -> u8 {
    ((raw & VMSA128_SKL_MASK) >> VMSA128_SKL_SHIFT) as u8
}

fn next_vmsa128_table_level(raw: u128, level: Level) -> Option<Level> {
    let next = level.as_i8().checked_add(vmsa128_raw_skl(raw) as i8 + 1)?;
    let next = Level::new(next);
    if next.is_after(Level::L3) {
        None
    } else {
        Some(next)
    }
}

fn decode_vmsa128_leaf_blocks(raw: u128, _level: Level) -> (RawFieldBlock<10>, RawFieldBlock<20>) {
    let low = RawFieldBlock::from_masked((raw >> VMSA128_FIELD_LO_SHIFT) & 0x3ff);
    let high = RawFieldBlock::from_masked((raw >> VMSA128_FIELD_HI_SHIFT) & 0xfffff);
    (low, high)
}

fn decode_vmsa128_table_blocks(raw: u128, _level: Level) -> (RawFieldBlock<8>, RawFieldBlock<20>) {
    let low = RawFieldBlock::from_masked((raw >> VMSA128_TABLE_LO_SHIFT) & 0xff);
    let high = RawFieldBlock::from_masked((raw >> VMSA128_FIELD_HI_SHIFT) & 0xfffff);
    (low, high)
}

fn encode_vmsa128_leaf_blocks(
    output_pa: PhysAddr,
    _level: Level,
    low: RawFieldBlock<10>,
    high: RawFieldBlock<20>,
) -> u128 {
    (output_pa.0 as u128 & VMSA128_ADDR_FIELD_MASK)
        | (low.bits() << VMSA128_FIELD_LO_SHIFT)
        | (high.bits() << VMSA128_FIELD_HI_SHIFT)
        | VMSA128_VALID
}

fn encode_vmsa128_table_blocks(
    table_pa: PhysAddr,
    low: RawFieldBlock<8>,
    high: RawFieldBlock<20>,
) -> u128 {
    let raw_high = high.bits() << VMSA128_FIELD_HI_SHIFT;
    (table_pa.0 as u128 & VMSA128_ADDR_FIELD_MASK)
        | (low.bits() << VMSA128_TABLE_LO_SHIFT)
        | raw_high
        | VMSA128_VALID
}

fn decode_vmsa128_output_address<G: TranslationGranule>(raw: u128, level: Level) -> PhysAddr {
    let address = (raw & VMSA128_ADDR_FIELD_MASK) as u64;
    let leaf_size_bits = vmsa128_leaf_size_bits::<G>(level);
    PhysAddr(align_down_bits(address, leaf_size_bits))
}

fn decode_vmsa128_table_address<G: TranslationGranule>(raw: u128, _level: Level) -> PhysAddr {
    let address = (raw & VMSA128_ADDR_FIELD_MASK) as u64;
    let stride_count = vmsa128_raw_skl(raw) + 1;
    let table_size_bits = G::SHIFT - 4;
    let table_size_bits = 4 + table_size_bits * stride_count;
    PhysAddr(align_down_bits(address, table_size_bits))
}

fn vmsa128_leaf_size_bits<G: TranslationGranule>(level: Level) -> u8 {
    let stride = G::SHIFT - 4;
    let levels = (Level::L3.as_i8() - level.as_i8()).max(0) as u8;
    G::SHIFT + stride * levels
}

fn align_down_bits(address: u64, bits: u8) -> u64 {
    if bits >= u64::BITS as u8 {
        0
    } else {
        address & !((1u64 << bits) - 1)
    }
}

fn leaf_attr_index(low: RawFieldBlock<10>) -> RawFieldBlock<4> {
    raw_block(low.bits() & 0xf)
}

fn leaf_nt(low: RawFieldBlock<10>) -> bool {
    low.bits() & (1 << 4) != 0
}

fn leaf_ndirty(low: RawFieldBlock<10>) -> bool {
    low.bits() & (1 << 5) != 0
}

fn leaf_sh(low: RawFieldBlock<10>) -> RawFieldBlock<2> {
    raw_block((low.bits() >> 6) & 0x3)
}

fn leaf_af(low: RawFieldBlock<10>) -> bool {
    low.bits() & (1 << 8) != 0
}

fn leaf_alias_bit(low: RawFieldBlock<10>) -> bool {
    low.bits() & (1 << 9) != 0
}

fn d128_hi_skl(high: RawFieldBlock<20>) -> RawFieldBlock<2> {
    raw_block((high.bits() >> 1) & 0x3)
}

fn d128_hi_contiguous(high: RawFieldBlock<20>) -> bool {
    high.bits() & (1 << 3) != 0
}

fn d128_hi_guarded(high: RawFieldBlock<20>) -> bool {
    high.bits() & (1 << 5) != 0
}

fn d128_hi_protected_or_assured_only(high: RawFieldBlock<20>) -> bool {
    high.bits() & (1 << 6) != 0
}

fn d128_hi_pii(high: RawFieldBlock<20>) -> RawFieldBlock<4> {
    raw_block((high.bits() >> 7) & 0xf)
}

fn d128_hi_poi(high: RawFieldBlock<20>) -> RawFieldBlock<4> {
    raw_block((high.bits() >> 15) & 0xf)
}

fn d128_hi_ns(high: RawFieldBlock<20>) -> bool {
    high.bits() & (1 << 19) != 0
}

fn table_nt(low: RawFieldBlock<8>) -> bool {
    low.bits() & (1 << 2) != 0
}

fn table_a(low: RawFieldBlock<8>) -> bool {
    low.bits() & (1 << 6) != 0
}

fn d128_table_hi_skl(high: RawFieldBlock<20>) -> RawFieldBlock<2> {
    raw_block((high.bits() >> 1) & 0x3)
}

fn d128_table_hi_disch(high: RawFieldBlock<20>) -> bool {
    high.bits() & (1 << 5) != 0
}

fn d128_table_hi_protected_or_assured_only(high: RawFieldBlock<20>) -> bool {
    high.bits() & (1 << 6) != 0
}

fn d128_table_hi_pxntable(high: RawFieldBlock<20>) -> bool {
    high.bits() & (1 << 15) != 0
}

fn d128_table_hi_uxntable_or_xntable(high: RawFieldBlock<20>) -> bool {
    high.bits() & (1 << 16) != 0
}

fn d128_table_hi_aptable(high: RawFieldBlock<20>) -> RawFieldBlock<2> {
    raw_block((high.bits() >> 17) & 0x3)
}

fn d128_table_hi_nstable(high: RawFieldBlock<20>) -> bool {
    high.bits() & (1 << 19) != 0
}

fn raw_block<const BITS: u8>(bits: u128) -> RawFieldBlock<BITS> {
    RawFieldBlock::from_masked(bits)
}

fn pack_leaf_low(
    attr_index: RawFieldBlock<4>,
    nt: bool,
    ndirty: bool,
    sh: RawFieldBlock<2>,
    af: bool,
    alias_bit: bool,
) -> RawFieldBlock<10> {
    raw_block(
        attr_index.bits()
            | ((nt as u128) << 4)
            | ((ndirty as u128) << 5)
            | (sh.bits() << 6)
            | ((af as u128) << 8)
            | ((alias_bit as u128) << 9),
    )
}

#[allow(clippy::too_many_arguments)]
fn pack_leaf_high(
    skl: RawFieldBlock<2>,
    contiguous: bool,
    guarded: bool,
    protected_or_assured_only: bool,
    pii: RawFieldBlock<4>,
    poi: RawFieldBlock<4>,
    ns: bool,
) -> RawFieldBlock<20> {
    raw_block(
        (skl.bits() << 1)
            | ((contiguous as u128) << 3)
            | ((guarded as u128) << 5)
            | ((protected_or_assured_only as u128) << 6)
            | (pii.bits() << 7)
            | (poi.bits() << 15)
            | ((ns as u128) << 19),
    )
}

fn pack_table_low(nt: bool, a: bool) -> RawFieldBlock<8> {
    raw_block(((nt as u128) << 2) | ((a as u128) << 6))
}

#[allow(clippy::too_many_arguments)]
fn pack_table_high(
    skl: RawFieldBlock<2>,
    disch: bool,
    protected_or_assured_only: bool,
    pxntable: bool,
    uxntable_or_xntable: bool,
    aptable: RawFieldBlock<2>,
    nstable: bool,
) -> RawFieldBlock<20> {
    raw_block(
        (skl.bits() << 1)
            | ((disch as u128) << 5)
            | ((protected_or_assured_only as u128) << 6)
            | ((pxntable as u128) << 15)
            | ((uxntable_or_xntable as u128) << 16)
            | (aptable.bits() << 17)
            | ((nstable as u128) << 19),
    )
}

impl Vmsa128Stage1LeafFields {
    #[allow(clippy::too_many_arguments)]
    pub fn from_arch_fields(
        attr_index: RawFieldBlock<4>,
        nt: bool,
        ndirty: bool,
        sh: RawFieldBlock<2>,
        af: bool,
        alias_bit: bool,
        skl: RawFieldBlock<2>,
        contiguous: bool,
        guarded: bool,
        protected: bool,
        pii: RawFieldBlock<4>,
        poi: RawFieldBlock<4>,
        ns: bool,
    ) -> Self {
        Self {
            low: pack_leaf_low(attr_index, nt, ndirty, sh, af, alias_bit),
            high: pack_leaf_high(skl, contiguous, guarded, protected, pii, poi, ns),
        }
    }

    pub fn attr_index(self) -> RawFieldBlock<4> {
        leaf_attr_index(self.low)
    }
    pub fn nt(self) -> bool {
        leaf_nt(self.low)
    }
    pub fn ndirty(self) -> bool {
        leaf_ndirty(self.low)
    }
    pub fn shareability(self) -> RawFieldBlock<2> {
        leaf_sh(self.low)
    }
    pub fn af(self) -> bool {
        leaf_af(self.low)
    }
    pub fn alias_bit(self) -> bool {
        leaf_alias_bit(self.low)
    }
    pub fn skl(self) -> RawFieldBlock<2> {
        d128_hi_skl(self.high)
    }
    pub fn contiguous(self) -> bool {
        d128_hi_contiguous(self.high)
    }
    pub fn guarded(self) -> bool {
        d128_hi_guarded(self.high)
    }
    pub fn protected(self) -> bool {
        d128_hi_protected_or_assured_only(self.high)
    }
    pub fn pii(self) -> RawFieldBlock<4> {
        d128_hi_pii(self.high)
    }
    pub fn poi(self) -> RawFieldBlock<4> {
        d128_hi_poi(self.high)
    }
    pub fn ns(self) -> bool {
        d128_hi_ns(self.high)
    }
}

impl Vmsa128Stage2LeafFields {
    #[allow(clippy::too_many_arguments)]
    pub fn from_arch_fields(
        attr_index: RawFieldBlock<4>,
        nt: bool,
        ndirty: bool,
        sh: RawFieldBlock<2>,
        af: bool,
        alias_bit: bool,
        skl: RawFieldBlock<2>,
        contiguous: bool,
        guarded: bool,
        assured_only: bool,
        pii: RawFieldBlock<4>,
        poi: RawFieldBlock<4>,
        ns: bool,
    ) -> Self {
        Self {
            low: pack_leaf_low(attr_index, nt, ndirty, sh, af, alias_bit),
            high: pack_leaf_high(skl, contiguous, guarded, assured_only, pii, poi, ns),
        }
    }

    pub fn attr_index(self) -> RawFieldBlock<4> {
        leaf_attr_index(self.low)
    }
    pub fn nt(self) -> bool {
        leaf_nt(self.low)
    }
    pub fn ndirty(self) -> bool {
        leaf_ndirty(self.low)
    }
    pub fn shareability(self) -> RawFieldBlock<2> {
        leaf_sh(self.low)
    }
    pub fn af(self) -> bool {
        leaf_af(self.low)
    }
    pub fn alias_bit(self) -> bool {
        leaf_alias_bit(self.low)
    }
    pub fn skl(self) -> RawFieldBlock<2> {
        d128_hi_skl(self.high)
    }
    pub fn contiguous(self) -> bool {
        d128_hi_contiguous(self.high)
    }
    pub fn guarded(self) -> bool {
        d128_hi_guarded(self.high)
    }
    pub fn assured_only(self) -> bool {
        d128_hi_protected_or_assured_only(self.high)
    }
    pub fn pii(self) -> RawFieldBlock<4> {
        d128_hi_pii(self.high)
    }
    pub fn poi(self) -> RawFieldBlock<4> {
        d128_hi_poi(self.high)
    }
    pub fn ns(self) -> bool {
        d128_hi_ns(self.high)
    }
}

impl Vmsa128Stage1TableFields {
    #[allow(clippy::too_many_arguments)]
    pub fn from_arch_fields(
        nt: bool,
        a: bool,
        skl: RawFieldBlock<2>,
        disch: bool,
        protected: bool,
        pxntable: bool,
        uxntable: bool,
        aptable: RawFieldBlock<2>,
        nstable: bool,
    ) -> Self {
        Self {
            low: pack_table_low(nt, a),
            high: pack_table_high(skl, disch, protected, pxntable, uxntable, aptable, nstable),
        }
    }

    pub fn nt(self) -> bool {
        table_nt(self.low)
    }
    pub fn a(self) -> bool {
        table_a(self.low)
    }
    pub fn skl(self) -> RawFieldBlock<2> {
        d128_table_hi_skl(self.high)
    }
    pub fn disch(self) -> bool {
        d128_table_hi_disch(self.high)
    }
    pub fn protected(self) -> bool {
        d128_table_hi_protected_or_assured_only(self.high)
    }
    pub fn pxntable(self) -> bool {
        d128_table_hi_pxntable(self.high)
    }
    pub fn uxntable(self) -> bool {
        d128_table_hi_uxntable_or_xntable(self.high)
    }
    pub fn aptable(self) -> RawFieldBlock<2> {
        d128_table_hi_aptable(self.high)
    }
    pub fn nstable(self) -> bool {
        d128_table_hi_nstable(self.high)
    }
}

impl Vmsa128Stage2TableFields {
    #[allow(clippy::too_many_arguments)]
    pub fn from_arch_fields(
        nt: bool,
        a: bool,
        skl: RawFieldBlock<2>,
        disch: bool,
        assured_only: bool,
        pxntable: bool,
        xntable: bool,
        aptable: RawFieldBlock<2>,
        nstable: bool,
    ) -> Self {
        Self {
            low: pack_table_low(nt, a),
            high: pack_table_high(
                skl,
                disch,
                assured_only,
                pxntable,
                xntable,
                aptable,
                nstable,
            ),
        }
    }

    pub fn nt(self) -> bool {
        table_nt(self.low)
    }
    pub fn a(self) -> bool {
        table_a(self.low)
    }
    pub fn skl(self) -> RawFieldBlock<2> {
        d128_table_hi_skl(self.high)
    }
    pub fn disch(self) -> bool {
        d128_table_hi_disch(self.high)
    }
    pub fn assured_only(self) -> bool {
        d128_table_hi_protected_or_assured_only(self.high)
    }
    pub fn pxntable(self) -> bool {
        d128_table_hi_pxntable(self.high)
    }
    pub fn xntable(self) -> bool {
        d128_table_hi_uxntable_or_xntable(self.high)
    }
    pub fn aptable(self) -> RawFieldBlock<2> {
        d128_table_hi_aptable(self.high)
    }
    pub fn nstable(self) -> bool {
        d128_table_hi_nstable(self.high)
    }
}
