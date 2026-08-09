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

/// Associates a descriptor format with the family that defines its semantic attribute shapes.
pub trait HasSemanticAttributeFamily: DescriptorFormat {
    type Family;
}

/// Selects semantic leaf and table types for an attribute family, stage, and regime.
pub trait SemanticAttributeFamilyTypes<S, R> {
    type Leaf: Copy;
    type Table: Copy;
}

/// Selects semantic leaf and table types for a descriptor format, stage, and regime.
pub trait SemanticAttributeTypes<S, R>: DescriptorFormat {
    type Leaf: Copy;
    type Table: Copy;
}

impl<F, S, R> SemanticAttributeTypes<S, R> for F
where
    F: HasSemanticAttributeFamily,
    F::Family: SemanticAttributeFamilyTypes<S, R>,
{
    type Leaf = <F::Family as SemanticAttributeFamilyTypes<S, R>>::Leaf;
    type Table = <F::Family as SemanticAttributeFamilyTypes<S, R>>::Table;
}

/// The semantic leaf attributes accepted for descriptor format `F` and regime `R`.
pub type SemanticLeafAttrs<F, R> =
    <F as SemanticAttributeTypes<<R as TranslationRegime>::Stage, R>>::Leaf;

/// The semantic table attributes accepted for descriptor format `F` and regime `R`.
pub type SemanticTableAttrs<F, R> =
    <F as SemanticAttributeTypes<<R as TranslationRegime>::Stage, R>>::Table;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64SemanticFamily;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa128SemanticFamily;

impl HasSemanticAttributeFamily for Vmsa64 {
    type Family = Vmsa64SemanticFamily;
}

impl HasSemanticAttributeFamily for Vmsa64Lpa2 {
    type Family = Vmsa64SemanticFamily;
}

impl HasSemanticAttributeFamily for Vmsa128 {
    type Family = Vmsa128SemanticFamily;
}

impl<R> SemanticAttributeFamilyTypes<Stage1, R> for Vmsa64SemanticFamily
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

impl<R> SemanticAttributeFamilyTypes<Stage2, R> for Vmsa64SemanticFamily
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

impl<R> SemanticAttributeFamilyTypes<Stage1, R> for Vmsa128SemanticFamily
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

impl<R> SemanticAttributeFamilyTypes<Stage2, R> for Vmsa128SemanticFamily
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
