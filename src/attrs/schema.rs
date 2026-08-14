use crate::config::format::{Vmsa64, Vmsa64Lpa2, Vmsa128};
use crate::descriptor::DescriptorFormat;
use crate::regime::{Stage1Regime, Stage2Regime, TranslationRegime};
use crate::translation::{Stage1, Stage2};

use super::{
    PrivilegeModel, SemanticStage1LeafAttrs, SemanticStage1TableAttrs, SemanticStage2LeafAttrs,
    SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
    SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs,
    SemanticVmsa128Stage1LeafControls, SemanticVmsa128Stage1TableAttrs,
    SemanticVmsa128Stage2LeafControls, SemanticVmsa128Stage2TableAttrs, Stage1EffectivePermissions,
    Stage1PasModel, Stage2LeafPermissions, Stage2PasContext, Stage2Permission,
};

/// Selects the semantic schema exposed by a descriptor format.
///
/// Sharing a schema only means that formats expose the same semantic leaf and table types. It
/// does not imply that they use the same raw encoding or descriptor layout.
pub trait HasSemanticSchema: DescriptorFormat {
    type Schema;
}

/// Selects semantic leaf and table types for a schema, translation stage, and regime.
pub trait SemanticSchemaTypes<S, R> {
    type Leaf: Copy;
    type Table: Copy;
}

/// This trait selects semantic leaf and table types for a descriptor format, translation stage,
/// and regime.
pub trait SemanticAttributeTypes<S, R>: DescriptorFormat {
    type Leaf: Copy;
    type Table: Copy;
}

impl<F, S, R> SemanticAttributeTypes<S, R> for F
where
    F: HasSemanticSchema,
    F::Schema: SemanticSchemaTypes<S, R>,
{
    type Leaf = <F::Schema as SemanticSchemaTypes<S, R>>::Leaf;
    type Table = <F::Schema as SemanticSchemaTypes<S, R>>::Table;
}

/// This alias selects the semantic leaf-attribute type for descriptor format `F` and regime `R`.
pub type SemanticLeafAttrs<F, R> =
    <F as SemanticAttributeTypes<<R as TranslationRegime>::Stage, R>>::Leaf;

/// This alias selects the semantic table-attribute type for descriptor format `F` and regime `R`.
pub type SemanticTableAttrs<F, R> =
    <F as SemanticAttributeTypes<<R as TranslationRegime>::Stage, R>>::Table;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64SemanticSchema;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128SemanticSchema;

impl HasSemanticSchema for Vmsa64 {
    type Schema = Vmsa64SemanticSchema;
}

impl HasSemanticSchema for Vmsa64Lpa2 {
    type Schema = Vmsa64SemanticSchema;
}

impl HasSemanticSchema for Vmsa128 {
    type Schema = Vmsa128SemanticSchema;
}

impl<R> SemanticSchemaTypes<Stage1, R> for Vmsa64SemanticSchema
where
    R: Stage1Regime<Stage = Stage1>,
    R::PasModel: Stage1PasModel,
{
    type Leaf = SemanticStage1LeafAttrs<
        <R::PrivilegeModel as PrivilegeModel>::LeafPermissions,
        <R::PasModel as Stage1PasModel>::LeafAttr,
        SemanticVmsa64Stage1LeafControls,
    >;

    type Table = SemanticStage1TableAttrs<
        <R::PrivilegeModel as PrivilegeModel>::TablePermissionLimits,
        <R::PasModel as Stage1PasModel>::TableAttr,
        SemanticVmsa64Stage1TableControls,
    >;
}

impl<R> SemanticSchemaTypes<Stage2, R> for Vmsa64SemanticSchema
where
    R: Stage2Regime<Stage = Stage2>,
    R::PasModel: Stage2PasContext,
{
    type Leaf = SemanticStage2LeafAttrs<
        Stage2LeafPermissions,
        <R::PasModel as Stage2PasContext>::OutputAddressSpaceAttr,
        SemanticVmsa64Stage2LeafControls,
    >;

    type Table = SemanticVmsa64Stage2TableAttrs;
}

impl<R> SemanticSchemaTypes<Stage1, R> for Vmsa128SemanticSchema
where
    R: Stage1Regime<Stage = Stage1>,
    R::PasModel: Stage1PasModel,
{
    type Leaf = SemanticStage1LeafAttrs<
        Stage1EffectivePermissions,
        <R::PasModel as Stage1PasModel>::LeafAttr,
        SemanticVmsa128Stage1LeafControls,
    >;

    type Table = SemanticVmsa128Stage1TableAttrs<<R::PasModel as Stage1PasModel>::TableAttr>;
}

impl<R> SemanticSchemaTypes<Stage2, R> for Vmsa128SemanticSchema
where
    R: Stage2Regime<Stage = Stage2>,
    R::PasModel: Stage2PasContext,
{
    type Leaf = SemanticStage2LeafAttrs<
        Stage2Permission,
        <R::PasModel as Stage2PasContext>::OutputAddressSpaceAttr,
        SemanticVmsa128Stage2LeafControls,
    >;

    type Table = SemanticVmsa128Stage2TableAttrs;
}
