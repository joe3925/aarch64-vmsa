mod codecs;
mod config;
mod pas;
mod permissions;
mod profile;
mod semantic;
mod vmsa128;
mod vmsa64;

pub use config::*;
pub use pas::*;
pub use permissions::*;
pub use profile::*;
pub use semantic::*;
pub use vmsa64::*;
pub use vmsa128::*;

use crate::address::{Level, TranslationGranule};
use crate::descriptor::DescriptorLayout;
use crate::descriptor::{DescriptorFormat, HasLayout};
use crate::translation::TranslationRegime;
use crate::translation::{TranslationStage, TranslationWalkProfile};

pub type StageOf<R> = <<R as TranslationRegime>::WalkProfile as TranslationWalkProfile>::Stage;

pub type AttrProfileOf<R> = <R as TranslationRegime>::AttrProfile;

pub type StageLayoutOf<F, S, G> = <F as HasLayout<S, G>>::Layout;

pub type StageLeafFieldsOf<F, S, G> =
    <StageLayoutOf<F, S, G> as DescriptorLayout<F, S, G>>::LeafFields;

pub type StageTableFieldsOf<F, S, G> =
    <StageLayoutOf<F, S, G> as DescriptorLayout<F, S, G>>::TableFields;

pub type LayoutOf<F, R, G> = StageLayoutOf<F, StageOf<R>, G>;

pub type LeafFieldsOf<F, R, G> =
    <LayoutOf<F, R, G> as DescriptorLayout<F, StageOf<R>, G>>::LeafFields;

pub type TableFieldsOf<F, R, G> =
    <LayoutOf<F, R, G> as DescriptorLayout<F, StageOf<R>, G>>::TableFields;

pub type LeafAttrsOf<F, R, G, C> =
    <AttrProfileOf<R> as AttributeCodec<F, StageOf<R>, G, C>>::LeafAttrs;

pub type TableAttrsOf<F, R, G, C> =
    <AttrProfileOf<R> as AttributeCodec<F, StageOf<R>, G, C>>::TableAttrs;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttrError {
    ConflictingAttributes {
        first: AttrKind,
        second: AttrKind,
    },
    UnencodablePermissions,
    InvalidOutputAddressSpace,
    InvalidShareability,
    ShareabilityMismatch {
        requested: Shareability,
        effective: Shareability,
    },
    MemoryAttributeNotConfigured,
    Mair2Unavailable,
    InvalidMairIndexWidth,
    UnencodableMemoryAttribute,
    PermissionIndirectionUnavailable,
    PermissionOverlayUnavailable,
    PermissionCombinationNotConfigured,
    InvalidD128Alias,
    InvalidD128Configuration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttrKind {
    Memory,
    Access,
    Execute,
    Shareability,
    AccessFlag,
    Global,
    Dirty,
    Contiguous,
    Security,
    Software,
    TableAccessLimit,
    TableExecuteLimit,
}

pub trait AttributeCodec<F, S, G, C>: AttributeProfile<S>
where
    F: DescriptorFormat + HasLayout<S, G>,
    S: TranslationStage,
    G: TranslationGranule,
    C: LiveAttributeConfiguration,
{
    type LeafAttrs;
    type TableAttrs;

    fn encode_leaf_attrs(
        resolver: &AttributeResolver<C>,
        attrs: Self::LeafAttrs,
        level: Level,
    ) -> Result<StageLeafFieldsOf<F, S, G>, AttrError>;

    fn decode_leaf_attrs(
        resolver: &AttributeResolver<C>,
        fields: StageLeafFieldsOf<F, S, G>,
        level: Level,
    ) -> Result<Self::LeafAttrs, AttrError>;

    fn encode_table_attrs(
        resolver: &AttributeResolver<C>,
        attrs: Self::TableAttrs,
        level: Level,
    ) -> Result<StageTableFieldsOf<F, S, G>, AttrError>;

    fn decode_table_attrs(
        resolver: &AttributeResolver<C>,
        fields: StageTableFieldsOf<F, S, G>,
        level: Level,
    ) -> Result<Self::TableAttrs, AttrError>;
}
