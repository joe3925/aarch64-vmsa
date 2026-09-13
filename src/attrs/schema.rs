use crate::config::format::{DescriptorEndian, Vmsa64, Vmsa64Lpa2, Vmsa128};
use crate::descriptor::{DescriptorFormat, PeDescriptors, SmmuV2Descriptors, SmmuV3Descriptors};
use crate::regime::{Stage1PrivilegeModel, Stage1Regime, Stage2Regime, TranslationRegime};
use crate::translation::{Stage1, Stage2};

use super::{
    PrivilegeModel, SemanticSmmuV2Stage2LeafControls, SemanticStage1LeafAttrs,
    SemanticStage1TableAttrs, SemanticStage2LeafAttrs, SemanticVmsa64Stage1LeafControls,
    SemanticVmsa64Stage1TableControls, SemanticVmsa64Stage2LeafControls,
    SemanticVmsa64Stage2TableAttrs, SemanticVmsa128Stage1LeafControls,
    SemanticVmsa128Stage1TableAttrs, SemanticVmsa128Stage2LeafControls,
    SemanticVmsa128Stage2TableAttrs, Stage1PasModel, Stage1Permissions, Stage2PasContext,
    Stage2Permissions,
};

/// Selects the semantic schema exposed by a descriptor format.
///
/// Sharing a schema only means that formats expose the same semantic leaf and table types. It
/// does not imply that they use the same raw encoding or descriptor layout.
pub trait HasSemanticSchema<I>: DescriptorFormat {
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
    R: TranslationRegime,
    F: HasSemanticSchema<R::DescriptorInterpretation>,
    <F as HasSemanticSchema<R::DescriptorInterpretation>>::Schema: SemanticSchemaTypes<S, R>,
{
    type Leaf =
        <<F as HasSemanticSchema<R::DescriptorInterpretation>>::Schema as SemanticSchemaTypes<
            S,
            R,
        >>::Leaf;
    type Table =
        <<F as HasSemanticSchema<R::DescriptorInterpretation>>::Schema as SemanticSchemaTypes<
            S,
            R,
        >>::Table;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmmuV2Vmsa64SemanticSchema;

macro_rules! pe_and_smmuv3_schema {
    ($format:ident, $schema:ty) => {
        impl<E: DescriptorEndian> HasSemanticSchema<PeDescriptors> for $format<E> {
            type Schema = $schema;
        }
        impl<E: DescriptorEndian> HasSemanticSchema<SmmuV3Descriptors> for $format<E> {
            type Schema = $schema;
        }
    };
}

pe_and_smmuv3_schema!(Vmsa64, Vmsa64SemanticSchema);
pe_and_smmuv3_schema!(Vmsa64Lpa2, Vmsa64SemanticSchema);
pe_and_smmuv3_schema!(Vmsa128, Vmsa128SemanticSchema);

impl<E: DescriptorEndian> HasSemanticSchema<SmmuV2Descriptors> for Vmsa64<E> {
    type Schema = SmmuV2Vmsa64SemanticSchema;
}

impl<R> SemanticSchemaTypes<Stage1, R> for SmmuV2Vmsa64SemanticSchema
where
    R: Stage1Regime<Stage = Stage1>,
    R::PasModel: Stage1PasModel,
{
    type Leaf = SemanticStage1LeafAttrs<
        Stage1Permissions,
        <R::PasModel as Stage1PasModel>::LeafAttr,
        SemanticVmsa64Stage1LeafControls,
    >;
    type Table = SemanticStage1TableAttrs<
        <Stage1PrivilegeModel<R> as PrivilegeModel>::TableRestrictions,
        <R::PasModel as Stage1PasModel>::TableAttr,
        SemanticVmsa64Stage1TableControls,
    >;
}

impl<R> SemanticSchemaTypes<Stage2, R> for SmmuV2Vmsa64SemanticSchema
where
    R: Stage2Regime<Stage = Stage2>,
    R::PasModel: Stage2PasContext,
{
    type Leaf = SemanticStage2LeafAttrs<
        Stage2Permissions,
        <R::PasModel as Stage2PasContext>::OutputAddressSpaceAttr,
        SemanticSmmuV2Stage2LeafControls,
    >;
    type Table = SemanticVmsa64Stage2TableAttrs;
}

impl<R> SemanticSchemaTypes<Stage1, R> for Vmsa64SemanticSchema
where
    R: Stage1Regime<Stage = Stage1>,
    R::PasModel: Stage1PasModel,
{
    type Leaf = SemanticStage1LeafAttrs<
        Stage1Permissions,
        <R::PasModel as Stage1PasModel>::LeafAttr,
        SemanticVmsa64Stage1LeafControls,
    >;

    type Table = SemanticStage1TableAttrs<
        <Stage1PrivilegeModel<R> as PrivilegeModel>::TableRestrictions,
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
        Stage2Permissions,
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
        Stage1Permissions,
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
        Stage2Permissions,
        <R::PasModel as Stage2PasContext>::OutputAddressSpaceAttr,
        SemanticVmsa128Stage2LeafControls,
    >;

    type Table = SemanticVmsa128Stage2TableAttrs;
}
