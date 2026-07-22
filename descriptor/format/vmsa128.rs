use core::marker::PhantomData;

use crate::address::{GranuleKind, Level, PhysAddr, TranslationGranule};
use crate::attrs::{
    FourBit, PermissionIndices, RawShareability, RawVmsa128Stage1LeafAttrs,
    RawVmsa128Stage1TableAttrs, RawVmsa128Stage2LeafAttrs, RawVmsa128Stage2TableAttrs,
    Stage1NotDirty, Stage2Dirty, TenBit,
};
use crate::descriptor::layout::vmsa128 as b;
use crate::table::TableTransition;
use crate::translation::{Stage1, Stage2};

use super::{
    DescriptorError, DescriptorKind, DescriptorLayout, HasLayout, NextTableDescriptor, Vmsa128,
    insert_address,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128Layout<S, G>(PhantomData<(S, G)>);

impl<G: TranslationGranule> HasLayout<Stage1, G> for Vmsa128 {
    type Layout = Vmsa128Layout<Stage1, G>;
}
impl<G: TranslationGranule> HasLayout<Stage2, G> for Vmsa128 {
    type Layout = Vmsa128Layout<Stage2, G>;
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa128, Stage1, G> for Vmsa128Layout<Stage1, G> {
    type LeafFields = RawVmsa128Stage1LeafAttrs;
    type TableFields = RawVmsa128Stage1TableAttrs;
    const ADDRESS_FIELD_MASK: u128 = b::ADDRESS_FIELD_MASK;

    fn kind(raw: u128, level: Level) -> DescriptorKind {
        kind(G::KIND, raw, level)
    }
    fn decode_leaf_fields(raw: u128, _level: Level) -> Self::LeafFields {
        RawVmsa128Stage1LeafAttrs {
            attr_index: FourBit::from_masked(b::D128_ATTR_INDEX::extract(raw)),
            bbm_nt: b::D128_NT::extract(raw) != 0,
            not_dirty: Stage1NotDirty::new(b::D128_STAGE1_NDIRTY::extract(raw) != 0),
            shareability: RawShareability::from_masked(b::D128_SHAREABILITY::extract(raw)),
            access_flag: b::D128_ACCESS_FLAG::extract(raw) != 0,
            alias_bit: b::D128_LEAF_ALIAS::extract(raw) != 0,
            contiguous: b::D128_CONTIGUOUS::extract(raw) != 0,
            guarded: b::D128_GUARDED::extract(raw) != 0,
            protected: b::D128_PROTECTED_OR_ASSURED_ONLY::extract(raw) != 0,
            permissions: PermissionIndices {
                pi: FourBit::from_masked(b::D128_PI_INDEX::extract(raw)),
                po: FourBit::from_masked(b::D128_PO_INDEX::extract(raw)),
            },
            ns: b::D128_NS_OR_NSTABLE::extract(raw) != 0,
            software: TenBit::from_masked(b::D128_SOFTWARE::extract(raw)),
        }
    }
    fn decode_table_fields(raw: u128, _level: Level) -> Self::TableFields {
        RawVmsa128Stage1TableAttrs {
            table_nt: b::D128_NT::extract(raw) != 0,
            access_flag: b::D128_ACCESS_FLAG::extract(raw) != 0,
            disch: b::D128_DISCH::extract(raw) != 0,
            protected: b::D128_PROTECTED_OR_ASSURED_ONLY::extract(raw) != 0,
            ns_table: b::D128_NS_OR_NSTABLE::extract(raw) != 0,
            software: TenBit::from_masked(b::D128_SOFTWARE::extract(raw)),
        }
    }
    fn leaf_descriptor(
        output_pa: PhysAddr,
        level: Level,
        f: Self::LeafFields,
    ) -> Result<u128, DescriptorError> {
        require_leaf_level::<G>(level)?;
        if f.bbm_nt && leaf_skl(level) == 0 {
            return Err(DescriptorError::InvalidNtBbmCombination { level });
        }
        let mut raw = 0;
        raw = insert_address(raw, output_pa, Self::ADDRESS_FIELD_MASK);
        raw = pack_common_leaf(
            raw,
            f.attr_index,
            f.bbm_nt,
            f.shareability,
            f.access_flag,
            f.alias_bit,
            level,
            f.contiguous,
            f.protected,
            f.permissions,
            f.ns,
        );
        raw = b::D128_GUARDED::insert(raw, f.guarded.into());
        raw = b::D128_STAGE1_NDIRTY::insert(raw, f.not_dirty.bit().into());
        raw = b::D128_SOFTWARE::insert(raw, f.software.bits().into());
        raw = b::D128_VALID::insert(raw, 1);
        check(raw, b::stage1_leaf::RES0_MASK, b::stage1_leaf::RES1_MASK)?;
        Ok(raw)
    }
    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<Vmsa128, G>,
        f: Self::TableFields,
    ) -> Result<u128, DescriptorError> {
        let skl = transition_skl::<G>(transition)?;
        if f.table_nt && skl == 0 {
            return Err(DescriptorError::ReservedFieldSet { bit: 6 });
        }
        let mut raw = 0;
        raw = insert_address(raw, table_pa, Self::ADDRESS_FIELD_MASK);
        raw = pack_common_table(raw, f.table_nt, f.access_flag, skl, f.disch, f.protected);
        raw = b::D128_NS_OR_NSTABLE::insert(raw, f.ns_table.into());
        raw = b::D128_SOFTWARE::insert(raw, f.software.bits().into());
        raw = b::D128_VALID::insert(raw, 1);
        check(raw, b::stage1_table::RES0_MASK, b::stage1_table::RES1_MASK)?;
        Ok(raw)
    }
    fn output_address(raw: u128, level: Level) -> PhysAddr {
        output_address::<G>(raw, level)
    }
    fn table_address(raw: u128, _level: Level) -> PhysAddr {
        table_address::<G>(raw)
    }
    fn next_table(raw: u128, level: Level) -> Option<NextTableDescriptor> {
        Some(NextTableDescriptor {
            address: table_address::<G>(raw),
            level: next_table_level(raw, level)?,
            stride_count: raw_skl(raw) + 1,
        })
    }
    fn supports_table_transition(t: TableTransition<Vmsa128, G>) -> bool {
        transition_skl::<G>(t).is_ok()
    }
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa128, Stage2, G> for Vmsa128Layout<Stage2, G> {
    type LeafFields = RawVmsa128Stage2LeafAttrs;
    type TableFields = RawVmsa128Stage2TableAttrs;
    const REQUIRED_FEATURES: crate::arch::FeatureRequirements =
        crate::arch::FeatureRequirements::NONE
            .with_d128()
            .with_d128_stage2();
    const ADDRESS_FIELD_MASK: u128 = b::ADDRESS_FIELD_MASK;

    fn kind(raw: u128, level: Level) -> DescriptorKind {
        kind(G::KIND, raw, level)
    }
    fn decode_leaf_fields(raw: u128, _level: Level) -> Self::LeafFields {
        RawVmsa128Stage2LeafAttrs {
            mem_attr: FourBit::from_masked(b::D128_ATTR_INDEX::extract(raw)),
            bbm_nt: b::D128_NT::extract(raw) != 0,
            dirty: Stage2Dirty::new(b::D128_STAGE2_DIRTY::extract(raw) != 0),
            shareability: RawShareability::from_masked(b::D128_SHAREABILITY::extract(raw)),
            access_flag: b::D128_ACCESS_FLAG::extract(raw) != 0,
            force_no_execute: b::D128_LEAF_ALIAS::extract(raw) != 0,
            contiguous: b::D128_CONTIGUOUS::extract(raw) != 0,
            assured_only: b::D128_PROTECTED_OR_ASSURED_ONLY::extract(raw) != 0,
            permissions: PermissionIndices {
                pi: FourBit::from_masked(b::D128_PI_INDEX::extract(raw)),
                po: FourBit::from_masked(b::D128_PO_INDEX::extract(raw)),
            },
            ns: b::D128_NS_OR_NSTABLE::extract(raw) != 0,
            software: TenBit::from_masked(b::D128_SOFTWARE::extract(raw)),
        }
    }
    fn decode_table_fields(raw: u128, _level: Level) -> Self::TableFields {
        RawVmsa128Stage2TableAttrs {
            table_nt: b::D128_NT::extract(raw) != 0,
            access_flag: b::D128_ACCESS_FLAG::extract(raw) != 0,
            software: TenBit::from_masked(b::D128_SOFTWARE::extract(raw)),
        }
    }
    fn leaf_descriptor(
        output_pa: PhysAddr,
        level: Level,
        f: Self::LeafFields,
    ) -> Result<u128, DescriptorError> {
        require_leaf_level::<G>(level)?;
        if f.bbm_nt && leaf_skl(level) == 0 {
            return Err(DescriptorError::InvalidNtBbmCombination { level });
        }
        let mut raw = 0;
        raw = insert_address(raw, output_pa, Self::ADDRESS_FIELD_MASK);
        raw = pack_common_leaf(
            raw,
            f.mem_attr,
            f.bbm_nt,
            f.shareability,
            f.access_flag,
            f.force_no_execute,
            level,
            f.contiguous,
            f.assured_only,
            f.permissions,
            f.ns,
        );
        raw = b::D128_STAGE2_DIRTY::insert(raw, f.dirty.bit().into());
        raw = b::D128_SOFTWARE::insert(raw, f.software.bits().into());
        raw = b::D128_VALID::insert(raw, 1);
        check(raw, b::stage2_leaf::RES0_MASK, b::stage2_leaf::RES1_MASK)?;
        Ok(raw)
    }
    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<Vmsa128, G>,
        f: Self::TableFields,
    ) -> Result<u128, DescriptorError> {
        let skl = transition_skl::<G>(transition)?;
        if f.table_nt && skl == 0 {
            return Err(DescriptorError::ReservedFieldSet { bit: 6 });
        }
        let mut raw = 0;
        raw = insert_address(raw, table_pa, Self::ADDRESS_FIELD_MASK);
        raw = b::D128_NT::insert(raw, f.table_nt.into());
        raw = b::D128_ACCESS_FLAG::insert(raw, f.access_flag.into());
        raw = b::D128_SKL::insert(raw, skl.into());
        raw = b::D128_SOFTWARE::insert(raw, f.software.bits().into());
        raw = b::D128_VALID::insert(raw, 1);
        check(raw, b::stage2_table::RES0_MASK, b::stage2_table::RES1_MASK)?;
        Ok(raw)
    }
    fn output_address(raw: u128, level: Level) -> PhysAddr {
        output_address::<G>(raw, level)
    }
    fn table_address(raw: u128, _level: Level) -> PhysAddr {
        table_address::<G>(raw)
    }
    fn next_table(raw: u128, level: Level) -> Option<NextTableDescriptor> {
        Some(NextTableDescriptor {
            address: table_address::<G>(raw),
            level: next_table_level(raw, level)?,
            stride_count: raw_skl(raw) + 1,
        })
    }
    fn supports_table_transition(t: TableTransition<Vmsa128, G>) -> bool {
        transition_skl::<G>(t).is_ok()
    }
}

#[allow(clippy::too_many_arguments)]
fn pack_common_leaf(
    mut raw: u128,
    memory: FourBit,
    nt: bool,
    sh: RawShareability,
    af: bool,
    alias: bool,
    level: Level,
    contiguous: bool,
    protected: bool,
    permissions: PermissionIndices,
    ns: bool,
) -> u128 {
    raw = b::D128_ATTR_INDEX::insert(raw, memory.bits().into());
    raw = b::D128_NT::insert(raw, nt.into());
    raw = b::D128_SHAREABILITY::insert(raw, sh.bits().into());
    raw = b::D128_ACCESS_FLAG::insert(raw, af.into());
    raw = b::D128_LEAF_ALIAS::insert(raw, alias.into());
    raw = b::D128_SKL::insert(raw, leaf_skl(level).into());
    raw = b::D128_CONTIGUOUS::insert(raw, contiguous.into());
    raw = b::D128_PROTECTED_OR_ASSURED_ONLY::insert(raw, protected.into());
    raw = b::D128_PI_INDEX::insert(raw, permissions.pi.bits().into());
    raw = b::D128_PO_INDEX::insert(raw, permissions.po.bits().into());
    raw = b::D128_NS_OR_NSTABLE::insert(raw, ns.into());
    raw
}

fn pack_common_table(
    mut raw: u128,
    nt: bool,
    af: bool,
    skl: u8,
    disch: bool,
    protected: bool,
) -> u128 {
    raw = b::D128_NT::insert(raw, nt.into());
    raw = b::D128_ACCESS_FLAG::insert(raw, af.into());
    raw = b::D128_SKL::insert(raw, skl.into());
    raw = b::D128_DISCH::insert(raw, disch.into());
    raw = b::D128_PROTECTED_OR_ASSURED_ONLY::insert(raw, protected.into());
    raw
}

pub(super) fn supports_leaf_level(granule: GranuleKind, level: Level) -> bool {
    let skip = Level::L3.as_i8() - level.as_i8();
    (0..=3).contains(&skip) && skl_supported(granule, skip as u8)
}

pub(crate) fn skl_supported(granule: GranuleKind, skl: u8) -> bool {
    !matches!(
        (granule, skl),
        (GranuleKind::Size16KiB | GranuleKind::Size64KiB, 3)
    )
}

fn leaf_skl(level: Level) -> u8 {
    let skip = Level::L3.as_i8() - level.as_i8();
    debug_assert!((0..=3).contains(&skip));
    skip as u8
}

fn transition_skl<G: TranslationGranule>(
    t: TableTransition<Vmsa128, G>,
) -> Result<u8, DescriptorError> {
    let step = t.level_step();
    if step != 0 && t.child().stride_count().raw() == step && skl_supported(G::KIND, step - 1) {
        Ok(step - 1)
    } else {
        Err(DescriptorError::InvalidTableTransition {
            parent_level: t.parent_level(),
            child_level: t.child_level(),
            stride_count: t.child().stride_count().raw(),
        })
    }
}

fn kind(granule: GranuleKind, raw: u128, level: Level) -> DescriptorKind {
    if b::D128_VALID::extract(raw) == 0 {
        return DescriptorKind::Invalid;
    }
    let skl = b::D128_SKL::extract(raw) as u8;
    if !skl_supported(granule, skl) {
        return DescriptorKind::Invalid;
    }
    match level.as_i8() + skl as i8 {
        sum if sum < Level::L3.as_i8() => DescriptorKind::Table,
        sum if sum == Level::L3.as_i8() && level == Level::L3 => DescriptorKind::Page,
        sum if sum == Level::L3.as_i8() => DescriptorKind::Block,
        _ => DescriptorKind::Invalid,
    }
}

fn raw_skl(raw: u128) -> u8 {
    b::D128_SKL::extract(raw) as u8
}

fn next_table_level(raw: u128, level: Level) -> Option<Level> {
    let next = Level::new(level.as_i8().checked_add(raw_skl(raw) as i8 + 1)?);
    (!next.is_after(Level::L3)).then_some(next)
}

fn output_address<G: TranslationGranule>(raw: u128, level: Level) -> PhysAddr {
    let address = (raw & b::ADDRESS_FIELD_MASK) as u64;
    let levels = (Level::L3.as_i8() - level.as_i8()).max(0) as u8;
    let bits = G::SHIFT + (G::SHIFT - 4) * levels;
    PhysAddr(align_down(address, bits))
}

fn table_address<G: TranslationGranule>(raw: u128) -> PhysAddr {
    let address = (raw & b::ADDRESS_FIELD_MASK) as u64;
    let bits = 4 + (G::SHIFT - 4) * (raw_skl(raw) + 1);
    PhysAddr(align_down(address, bits))
}

const fn align_down(address: u64, bits: u8) -> u64 {
    if bits >= 64 {
        0
    } else {
        address & !((1u64 << bits) - 1)
    }
}

fn require_leaf_level<G: TranslationGranule>(level: Level) -> Result<(), DescriptorError> {
    if supports_leaf_level(G::KIND, level) {
        Ok(())
    } else {
        Err(DescriptorError::InvalidLeafLevel { level })
    }
}

fn check(raw: u128, res0: u128, res1: u128) -> Result<(), DescriptorError> {
    if raw & res0 != 0 || raw & res1 != res1 {
        Err(DescriptorError::InvalidReservedBitState)
    } else {
        Ok(())
    }
}
