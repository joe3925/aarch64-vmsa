use crate::address::{Granule4KiB, Granule16KiB, Granule64KiB, Level, TranslationGranule};
use crate::attrs::{
    AttrError, D128AliasConfig, FourBit, PrivilegeModel, RawVmsa64Stage1LeafAttrs,
    RawVmsa64Stage1TableAttrs, RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs,
    RawVmsa128Stage1LeafAttrs, RawVmsa128Stage1TableAttrs, RawVmsa128Stage2LeafAttrs,
    RawVmsa128Stage2TableAttrs, SemanticStage1LeafAttrs, SemanticStage1TableAttrs,
    SemanticStage2LeafAttrs, SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
    SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs,
    SemanticVmsa128Stage1LeafControls, SemanticVmsa128Stage1TableAttrs,
    SemanticVmsa128Stage2LeafControls, SemanticVmsa128Stage2TableAttrs, Shareability,
    ShareabilityConfig, Stage1EffectivePermissions, Stage1MemoryConfig, Stage1PasModel,
    Stage1PermissionConfig, Stage2LeafPermissions, Stage2MemoryConfig, Stage2PasContext,
    Stage2Permission, Stage2PermissionConfig, Stage2PermissionModel, TenBit,
};
use crate::descriptor::{
    DescriptorFormat, DescriptorLayout, HasLayout, Vmsa64, Vmsa64Lpa2, Vmsa128,
};
use crate::regime::*;
use crate::translation::Stage1;

use super::*;

pub trait AttributeCodec<R, G, Cfg>: DescriptorFormat
where
    Self: HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    RegimeLayout<Self, R, G>: DescriptorLayout<R::Stage, G, Format = Self, LeafFields = Self::RawLeaf, TableFields = Self::RawTable>,
{
    type SemanticLeaf: Copy;
    type SemanticTable: Copy;
    type RawLeaf: Copy;
    type RawTable: Copy;

    fn resolve_leaf(
        config: &Cfg,
        level: Level,
        attrs: Self::SemanticLeaf,
    ) -> Result<Self::RawLeaf, AttrError>;

    fn resolve_table(
        config: &Cfg,
        level: Level,
        attrs: Self::SemanticTable,
    ) -> Result<Self::RawTable, AttrError>;

    fn decode_leaf(
        config: &Cfg,
        level: Level,
        raw: Self::RawLeaf,
    ) -> Result<Self::SemanticLeaf, AttrError>;

    fn decode_table(
        config: &Cfg,
        level: Level,
        raw: Self::RawTable,
    ) -> Result<Self::SemanticTable, AttrError>;
}

trait Lpa2GranulePolicy<C>: TranslationGranule {
    fn encode_shareability(config: &C, requested: Shareability) -> Result<(), AttrError>;
    fn decode_shareability(config: &C, decoded: &mut Shareability) -> Result<(), AttrError>;
}

macro_rules! lpa2_ds_granule {
    ($granule:ty) => {
        impl<C: ShareabilityConfig> Lpa2GranulePolicy<C> for $granule {
            fn encode_shareability(config: &C, requested: Shareability) -> Result<(), AttrError> {
                require_effective_shareability(config, requested)
            }
            fn decode_shareability(
                config: &C,
                decoded: &mut Shareability,
            ) -> Result<(), AttrError> {
                *decoded = config.effective_shareability();
                Ok(())
            }
        }
    };
}
lpa2_ds_granule!(Granule4KiB);
lpa2_ds_granule!(Granule16KiB);

impl<C: ShareabilityConfig> Lpa2GranulePolicy<C> for Granule64KiB {
    fn encode_shareability(_: &C, _: Shareability) -> Result<(), AttrError> {
        Ok(())
    }
    fn decode_shareability(_: &C, _: &mut Shareability) -> Result<(), AttrError> {
        Ok(())
    }
}

macro_rules! impl_stage1_codecs {
    () => {
        impl<R, G, Cfg> AttributeCodec<R, G, Cfg> for Vmsa64
        where
            R: Stage1Regime<Stage = Stage1>,
            G: TranslationGranule,
            Cfg: Stage1MemoryConfig,
            R::PrivilegeModel: Stage1DirectPermissionModel,
            R::PasModel: Stage1PasResolver,
        {
            type SemanticLeaf = SemanticStage1LeafAttrs<
                <R::PrivilegeModel as PrivilegeModel>::LeafPermissions,
                <R::PasModel as Stage1PasModel>::LeafAttr,
                SemanticVmsa64Stage1LeafControls,
            >;
            type SemanticTable = SemanticStage1TableAttrs<
                <R::PrivilegeModel as PrivilegeModel>::TablePermissionLimits,
                <R::PasModel as Stage1PasModel>::TableAttr,
                SemanticVmsa64Stage1TableControls,
            >;
            type RawLeaf = RawVmsa64Stage1LeafAttrs;
            type RawTable = RawVmsa64Stage1TableAttrs;

            fn resolve_leaf(config: &Cfg, _: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                resolve_vmsa64_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(config, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> {
                resolve_vmsa64_stage1_table::<R::PrivilegeModel, R::PasModel>(attrs)
            }
            fn decode_leaf(config: &Cfg, _: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> {
                decode_vmsa64_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(config, raw)
            }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> {
                decode_vmsa64_stage1_table::<R::PrivilegeModel, R::PasModel>(raw)
            }
        }

        impl<R, G, Cfg> AttributeCodec<R, G, Cfg> for Vmsa64Lpa2
        where
            R: Stage1Regime<Stage = Stage1>,
            G: TranslationGranule + Lpa2GranulePolicy<Cfg>,
            Cfg: Stage1MemoryConfig + ShareabilityConfig,
            R::PrivilegeModel: Stage1DirectPermissionModel,
            R::PasModel: Stage1PasResolver,
        {
            type SemanticLeaf = SemanticStage1LeafAttrs<
                <R::PrivilegeModel as PrivilegeModel>::LeafPermissions,
                <R::PasModel as Stage1PasModel>::LeafAttr,
                SemanticVmsa64Stage1LeafControls,
            >;
            type SemanticTable = SemanticStage1TableAttrs<
                <R::PrivilegeModel as PrivilegeModel>::TablePermissionLimits,
                <R::PasModel as Stage1PasModel>::TableAttr,
                SemanticVmsa64Stage1TableControls,
            >;
            type RawLeaf = RawVmsa64Stage1LeafAttrs;
            type RawTable = RawVmsa64Stage1TableAttrs;

            fn resolve_leaf(config: &Cfg, _: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                G::encode_shareability(config, attrs.controls.shareability)?;
                resolve_vmsa64_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(config, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> {
                resolve_vmsa64_stage1_table::<R::PrivilegeModel, R::PasModel>(attrs)
            }
            fn decode_leaf(config: &Cfg, _: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> {
                let mut attrs = decode_vmsa64_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(config, raw)?;
                G::decode_shareability(config, &mut attrs.controls.shareability)?;
                Ok(attrs)
            }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> {
                decode_vmsa64_stage1_table::<R::PrivilegeModel, R::PasModel>(raw)
            }
        }

        impl<R, G, Cfg> AttributeCodec<R, G, Cfg> for Vmsa128
        where
            R: Stage1Regime<Stage = Stage1>,
            G: TranslationGranule,
            Cfg: Stage1MemoryConfig + Stage1PermissionConfig + D128AliasConfig,
            R::PasModel: Stage1PasResolver,
        {
            type SemanticLeaf = SemanticStage1LeafAttrs<
                Stage1EffectivePermissions,
                <R::PasModel as Stage1PasModel>::LeafAttr,
                SemanticVmsa128Stage1LeafControls,
            >;
            type SemanticTable = SemanticVmsa128Stage1TableAttrs<
                <R::PasModel as Stage1PasModel>::TableAttr,
            >;
            type RawLeaf = RawVmsa128Stage1LeafAttrs;
            type RawTable = RawVmsa128Stage1TableAttrs;

            fn resolve_leaf(config: &Cfg, level: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                resolve_vmsa128_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(config, level, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> {
                resolve_vmsa128_stage1_table::<R::PasModel>(attrs)
            }
            fn decode_leaf(config: &Cfg, level: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> {
                let attrs = decode_vmsa128_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(config, raw)?;
                if attrs.controls.bbm_nt && level == Level::L3 {
                    return Err(AttrError::InvalidD128Configuration);
                }
                Ok(attrs)
            }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> {
                decode_vmsa128_stage1_table::<R::PasModel>(raw)
            }
        }
    };
}

impl_stage1_codecs!();

macro_rules! impl_stage2_codecs {
    ($regime:ident) => {
        impl<P, G, Cfg> AttributeCodec<$regime<P>, G, Cfg> for Vmsa64
        where
            P: Stage2PermissionModel,
            G: TranslationGranule,
            Cfg: Stage2MemoryConfig,
            <$regime<P> as TranslationRegime>::PasModel:
                Stage2PasContext + Stage2PasResolver<Vmsa64, Cfg, Software = FourBit>,
        {
            type SemanticLeaf = SemanticStage2LeafAttrs<Stage2LeafPermissions, <<$regime<P> as TranslationRegime>::PasModel as Stage2PasContext>::OutputAddressSpaceAttr, SemanticVmsa64Stage2LeafControls>;
            type SemanticTable = SemanticVmsa64Stage2TableAttrs;
            type RawLeaf = RawVmsa64Stage2LeafAttrs;
            type RawTable = RawVmsa64Stage2TableAttrs;
            fn resolve_leaf(config: &Cfg, _: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                resolve_vmsa64_stage2_leaf::<P, <$regime<P> as TranslationRegime>::PasModel, Cfg>(config, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> { resolve_vmsa64_stage2_table(attrs) }
            fn decode_leaf(config: &Cfg, _: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> { decode_vmsa64_stage2_leaf::<P, <$regime<P> as TranslationRegime>::PasModel, Cfg>(config, raw) }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> { decode_vmsa64_stage2_table(raw) }
        }

        impl<P, G, Cfg> AttributeCodec<$regime<P>, G, Cfg> for Vmsa64Lpa2
        where
            P: Stage2PermissionModel,
            G: TranslationGranule + Lpa2GranulePolicy<Cfg>,
            Cfg: Stage2MemoryConfig + ShareabilityConfig,
            <$regime<P> as TranslationRegime>::PasModel:
                Stage2PasContext + Stage2PasResolver<Vmsa64, Cfg, Software = FourBit>,
        {
            type SemanticLeaf = SemanticStage2LeafAttrs<Stage2LeafPermissions, <<$regime<P> as TranslationRegime>::PasModel as Stage2PasContext>::OutputAddressSpaceAttr, SemanticVmsa64Stage2LeafControls>;
            type SemanticTable = SemanticVmsa64Stage2TableAttrs;
            type RawLeaf = RawVmsa64Stage2LeafAttrs;
            type RawTable = RawVmsa64Stage2TableAttrs;
            fn resolve_leaf(config: &Cfg, _: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                G::encode_shareability(config, attrs.controls.shareability)?;
                resolve_vmsa64_stage2_leaf::<P, <$regime<P> as TranslationRegime>::PasModel, Cfg>(config, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> { resolve_vmsa64_stage2_table(attrs) }
            fn decode_leaf(config: &Cfg, _: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> {
                let mut attrs = decode_vmsa64_stage2_leaf::<P, <$regime<P> as TranslationRegime>::PasModel, Cfg>(config, raw)?;
                G::decode_shareability(config, &mut attrs.controls.shareability)?;
                Ok(attrs)
            }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> { decode_vmsa64_stage2_table(raw) }
        }

        impl<P, G, Cfg> AttributeCodec<$regime<P>, G, Cfg> for Vmsa128
        where
            P: Stage2PermissionModel,
            G: TranslationGranule,
            Cfg: Stage2MemoryConfig + Stage2PermissionConfig,
            <$regime<P> as TranslationRegime>::PasModel:
                Stage2PasContext + Stage2PasResolver<Vmsa128, Cfg, Software = TenBit>,
        {
            type SemanticLeaf = SemanticStage2LeafAttrs<Stage2Permission, <<$regime<P> as TranslationRegime>::PasModel as Stage2PasContext>::OutputAddressSpaceAttr, SemanticVmsa128Stage2LeafControls>;
            type SemanticTable = SemanticVmsa128Stage2TableAttrs;
            type RawLeaf = RawVmsa128Stage2LeafAttrs;
            type RawTable = RawVmsa128Stage2TableAttrs;
            fn resolve_leaf(config: &Cfg, level: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                resolve_vmsa128_stage2_leaf::<<$regime<P> as TranslationRegime>::PasModel, Cfg>(config, level, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> { resolve_vmsa128_stage2_table(attrs) }
            fn decode_leaf(config: &Cfg, level: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> {
                let attrs = decode_vmsa128_stage2_leaf::<<$regime<P> as TranslationRegime>::PasModel, Cfg>(config, raw)?;
                if attrs.controls.bbm_nt && level == Level::L3 {
                    return Err(AttrError::InvalidD128Configuration);
                }
                Ok(attrs)
            }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> { decode_vmsa128_stage2_table(raw) }
        }
    };
}

impl_stage2_codecs!(NonSecureEl2Stage2);
impl_stage2_codecs!(SecureEl2SecureIpaStage2);
impl_stage2_codecs!(SecureEl2NonSecureIpaStage2);
impl_stage2_codecs!(RealmEl2Stage2);
