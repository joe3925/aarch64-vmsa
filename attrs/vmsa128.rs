use core::marker::PhantomData;

use crate::layout::RawFieldBlock;

use super::{
    DirtyState, EffectivePermissions, FeatureDependentLeafAlias, MemoryAttributes,
    MemoryTransience, OutputAddressSpace, PermissionModel, Shareability, Stage1PasModel,
    Stage2PasContext, Stage2TablePermissions,
};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum D128SkipLevels {
    None = 0,
    One = 1,
    Two = 2,
    Three = 3,
}

impl D128SkipLevels {
    pub(crate) const fn from_bits(bits: u128) -> Self {
        match bits & 0b11 {
            0 => Self::None,
            1 => Self::One,
            2 => Self::Two,
            _ => Self::Three,
        }
    }

    pub(crate) const fn raw(self) -> RawFieldBlock<2> {
        RawFieldBlock::from_masked(self as u128)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128Stage1LeafAttrs<A>
where
    A: Stage1PasModel,
{
    pub memory: MemoryAttributes,
    pub permissions: EffectivePermissions,
    pub pas: A::LeafAttr,
    pub transience: MemoryTransience,
    pub dirty_state: DirtyState,
    pub shareability: Shareability,
    pub access_flag: bool,
    pub global: bool,
    pub contiguous: bool,
    pub guarded: bool,
    pub protected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128Stage1TableAttrs<P, A>
where
    P: PermissionModel,
    A: Stage1PasModel,
{
    pub permissions: P::TablePermissions,
    pub pas: A::TableAttr,
    pub transience: MemoryTransience,
    pub access_flag: bool,
    pub skip_levels: D128SkipLevels,
    pub discharge: bool,
    pub protected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128Stage2LeafAttrs<X>
where
    X: Stage2PasContext,
{
    pub memory: MemoryAttributes,
    pub permissions: EffectivePermissions,
    pub transience: MemoryTransience,
    pub dirty_state: DirtyState,
    pub shareability: Shareability,
    pub access_flag: bool,
    pub alias: FeatureDependentLeafAlias,
    pub contiguous: bool,
    pub guarded: bool,
    pub assured_only: bool,
    pub output_address_space: OutputAddressSpace,
    context: PhantomData<X>,
}

impl<X> Vmsa128Stage2LeafAttrs<X>
where
    X: Stage2PasContext,
{
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        memory: MemoryAttributes,
        permissions: EffectivePermissions,
        transience: MemoryTransience,
        dirty_state: DirtyState,
        shareability: Shareability,
        access_flag: bool,
        alias: FeatureDependentLeafAlias,
        contiguous: bool,
        guarded: bool,
        assured_only: bool,
        output_address_space: OutputAddressSpace,
    ) -> Self {
        Self {
            memory,
            permissions,
            transience,
            dirty_state,
            shareability,
            access_flag,
            alias,
            contiguous,
            guarded,
            assured_only,
            output_address_space,
            context: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128Stage2TableAttrs<X>
where
    X: Stage2PasContext,
{
    pub permissions: Stage2TablePermissions,
    pub transience: MemoryTransience,
    pub access_flag: bool,
    pub skip_levels: D128SkipLevels,
    pub discharge: bool,
    pub assured_only: bool,
    pub output_address_space: OutputAddressSpace,
    context: PhantomData<X>,
}

impl<X> Vmsa128Stage2TableAttrs<X>
where
    X: Stage2PasContext,
{
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        permissions: Stage2TablePermissions,
        transience: MemoryTransience,
        access_flag: bool,
        skip_levels: D128SkipLevels,
        discharge: bool,
        assured_only: bool,
        output_address_space: OutputAddressSpace,
    ) -> Self {
        Self {
            permissions,
            transience,
            access_flag,
            skip_levels,
            discharge,
            assured_only,
            output_address_space,
            context: PhantomData,
        }
    }
}
