use crate::address::{Granule4KiB, Granule16KiB, Granule64KiB, Level, TranslationGranule};
use crate::attrs::{
    AttrError, D128AliasConfig, PasConfig, PrivilegeModel, RawVmsa64Stage1LeafAttrs,
    RawVmsa64Stage1TableAttrs, RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs,
    RawVmsa128Stage1LeafAttrs, RawVmsa128Stage1TableAttrs, RawVmsa128Stage2LeafAttrs,
    RawVmsa128Stage2TableAttrs, RealmOrNonSecurePa, SecureSelectablePa, SemanticStage1LeafAttrs,
    SemanticStage1TableAttrs, SemanticStage2LeafAttrs, SemanticVmsa64Stage1LeafControls,
    SemanticVmsa64Stage1TableControls, SemanticVmsa64Stage2LeafControls,
    SemanticVmsa64Stage2TableAttrs, SemanticVmsa128Stage1LeafControls,
    SemanticVmsa128Stage1TableAttrs, SemanticVmsa128Stage2LeafControls,
    SemanticVmsa128Stage2TableAttrs, Shareability, ShareabilityConfig, Stage1EffectivePermissions,
    Stage1MemoryConfig, Stage1PasModel, Stage1PermissionConfig, Stage2LeafPermissions,
    Stage2MemoryConfig, Stage2Permission, Stage2PermissionConfig, Stage2PermissionModel,
};
use crate::descriptor::{
    DescriptorFormat, DescriptorLayout, HasLayout, Vmsa64, Vmsa64Lpa2, Vmsa128,
};
use crate::regime::*;

use super::*;

pub trait AttributeCodec<F, R, G, Cfg>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    LayoutOf<F, R, G>: DescriptorLayout<F, StageOf<R>, G, LeafFields = Self::RawLeaf, TableFields = Self::RawTable>,
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

#[derive(Clone, Copy, Debug, Default)]
pub struct VmsaAttributeCodec;

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
    ($regime:ty) => {
        impl<G, Cfg> AttributeCodec<Vmsa64, $regime, G, Cfg> for VmsaAttributeCodec
        where
            G: TranslationGranule,
            Cfg: Stage1MemoryConfig,
            <$regime as Stage1Regime>::PrivilegeModel: Stage1DirectPermissionModel,
            <$regime as TranslationRegime>::PasModel: Stage1PasResolver,
        {
            type SemanticLeaf = SemanticStage1LeafAttrs<
                <<$regime as Stage1Regime>::PrivilegeModel as PrivilegeModel>::LeafPermissions,
                <<$regime as TranslationRegime>::PasModel as Stage1PasModel>::LeafAttr,
                SemanticVmsa64Stage1LeafControls,
            >;
            type SemanticTable = SemanticStage1TableAttrs<
                <<$regime as Stage1Regime>::PrivilegeModel as PrivilegeModel>::TablePermissionLimits,
                <<$regime as TranslationRegime>::PasModel as Stage1PasModel>::TableAttr,
                SemanticVmsa64Stage1TableControls,
            >;
            type RawLeaf = RawVmsa64Stage1LeafAttrs;
            type RawTable = RawVmsa64Stage1TableAttrs;

            fn resolve_leaf(config: &Cfg, _: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                resolve_vmsa64_stage1_leaf::<<$regime as Stage1Regime>::PrivilegeModel, <$regime as TranslationRegime>::PasModel, Cfg>(config, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> {
                resolve_vmsa64_stage1_table::<<$regime as Stage1Regime>::PrivilegeModel, <$regime as TranslationRegime>::PasModel>(attrs)
            }
            fn decode_leaf(config: &Cfg, _: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> {
                decode_vmsa64_stage1_leaf::<<$regime as Stage1Regime>::PrivilegeModel, <$regime as TranslationRegime>::PasModel, Cfg>(config, raw)
            }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> {
                decode_vmsa64_stage1_table::<<$regime as Stage1Regime>::PrivilegeModel, <$regime as TranslationRegime>::PasModel>(raw)
            }
        }

        impl<G, Cfg> AttributeCodec<Vmsa64Lpa2, $regime, G, Cfg> for VmsaAttributeCodec
        where
            G: TranslationGranule + Lpa2GranulePolicy<Cfg>,
            Cfg: Stage1MemoryConfig + ShareabilityConfig,
            <$regime as Stage1Regime>::PrivilegeModel: Stage1DirectPermissionModel,
            <$regime as TranslationRegime>::PasModel: Stage1PasResolver,
        {
            type SemanticLeaf = SemanticStage1LeafAttrs<
                <<$regime as Stage1Regime>::PrivilegeModel as PrivilegeModel>::LeafPermissions,
                <<$regime as TranslationRegime>::PasModel as Stage1PasModel>::LeafAttr,
                SemanticVmsa64Stage1LeafControls,
            >;
            type SemanticTable = SemanticStage1TableAttrs<
                <<$regime as Stage1Regime>::PrivilegeModel as PrivilegeModel>::TablePermissionLimits,
                <<$regime as TranslationRegime>::PasModel as Stage1PasModel>::TableAttr,
                SemanticVmsa64Stage1TableControls,
            >;
            type RawLeaf = RawVmsa64Stage1LeafAttrs;
            type RawTable = RawVmsa64Stage1TableAttrs;

            fn resolve_leaf(config: &Cfg, _: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                G::encode_shareability(config, attrs.controls.shareability)?;
                resolve_vmsa64_stage1_leaf::<<$regime as Stage1Regime>::PrivilegeModel, <$regime as TranslationRegime>::PasModel, Cfg>(config, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> {
                resolve_vmsa64_stage1_table::<<$regime as Stage1Regime>::PrivilegeModel, <$regime as TranslationRegime>::PasModel>(attrs)
            }
            fn decode_leaf(config: &Cfg, _: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> {
                let mut attrs = decode_vmsa64_stage1_leaf::<<$regime as Stage1Regime>::PrivilegeModel, <$regime as TranslationRegime>::PasModel, Cfg>(config, raw)?;
                G::decode_shareability(config, &mut attrs.controls.shareability)?;
                Ok(attrs)
            }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> {
                decode_vmsa64_stage1_table::<<$regime as Stage1Regime>::PrivilegeModel, <$regime as TranslationRegime>::PasModel>(raw)
            }
        }

        impl<G, Cfg> AttributeCodec<Vmsa128, $regime, G, Cfg> for VmsaAttributeCodec
        where
            G: TranslationGranule,
            Cfg: Stage1MemoryConfig + Stage1PermissionConfig + D128AliasConfig,
            <$regime as TranslationRegime>::PasModel: Stage1PasResolver,
        {
            type SemanticLeaf = SemanticStage1LeafAttrs<
                Stage1EffectivePermissions,
                <<$regime as TranslationRegime>::PasModel as Stage1PasModel>::LeafAttr,
                SemanticVmsa128Stage1LeafControls,
            >;
            type SemanticTable = SemanticVmsa128Stage1TableAttrs<
                <<$regime as TranslationRegime>::PasModel as Stage1PasModel>::TableAttr,
            >;
            type RawLeaf = RawVmsa128Stage1LeafAttrs;
            type RawTable = RawVmsa128Stage1TableAttrs;

            fn resolve_leaf(config: &Cfg, level: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                resolve_vmsa128_stage1_leaf::<<$regime as Stage1Regime>::PrivilegeModel, <$regime as TranslationRegime>::PasModel, Cfg>(config, level, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> {
                resolve_vmsa128_stage1_table::<<$regime as TranslationRegime>::PasModel>(attrs)
            }
            fn decode_leaf(config: &Cfg, level: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> {
                let attrs = decode_vmsa128_stage1_leaf::<<$regime as Stage1Regime>::PrivilegeModel, <$regime as TranslationRegime>::PasModel, Cfg>(config, raw)?;
                if attrs.controls.bbm_nt && level == Level::L3 {
                    return Err(AttrError::InvalidD128Configuration);
                }
                Ok(attrs)
            }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> {
                decode_vmsa128_stage1_table::<<$regime as TranslationRegime>::PasModel>(raw)
            }
        }
    };
}

impl_stage1_codecs!(NonSecureEl1Stage1);
impl_stage1_codecs!(SecureEl1Stage1);
impl_stage1_codecs!(RealmEl1Stage1);
impl_stage1_codecs!(NonSecureEl2Stage1);
impl_stage1_codecs!(SecureEl2Stage1);
impl_stage1_codecs!(RealmEl2Stage1);
impl_stage1_codecs!(NonSecureEl2HostStage1);
impl_stage1_codecs!(SecureEl2HostStage1);
impl_stage1_codecs!(RealmEl2HostStage1);
impl_stage1_codecs!(RootEl3Stage1);

macro_rules! impl_stage2_codecs {
    ($regime:ident, $pas:ty, $resolve64:ident, $decode64:ident, $resolve128:ident, $decode128:ident, [$($extra:path),*]) => {
        impl<P, G, Cfg> AttributeCodec<Vmsa64, $regime<P>, G, Cfg> for VmsaAttributeCodec
        where
            P: Stage2PermissionModel,
            G: TranslationGranule,
            Cfg: Stage2MemoryConfig $(+ $extra)*,
        {
            type SemanticLeaf = SemanticStage2LeafAttrs<Stage2LeafPermissions, $pas, SemanticVmsa64Stage2LeafControls>;
            type SemanticTable = SemanticVmsa64Stage2TableAttrs;
            type RawLeaf = RawVmsa64Stage2LeafAttrs;
            type RawTable = RawVmsa64Stage2TableAttrs;
            fn resolve_leaf(config: &Cfg, _: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                $resolve64::<P, Cfg>(config, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> { resolve_vmsa64_stage2_table(attrs) }
            fn decode_leaf(config: &Cfg, _: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> { $decode64::<P, Cfg>(config, raw) }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> { decode_vmsa64_stage2_table(raw) }
        }

        impl<P, G, Cfg> AttributeCodec<Vmsa64Lpa2, $regime<P>, G, Cfg> for VmsaAttributeCodec
        where
            P: Stage2PermissionModel,
            G: TranslationGranule + Lpa2GranulePolicy<Cfg>,
            Cfg: Stage2MemoryConfig + ShareabilityConfig $(+ $extra)*,
        {
            type SemanticLeaf = SemanticStage2LeafAttrs<Stage2LeafPermissions, $pas, SemanticVmsa64Stage2LeafControls>;
            type SemanticTable = SemanticVmsa64Stage2TableAttrs;
            type RawLeaf = RawVmsa64Stage2LeafAttrs;
            type RawTable = RawVmsa64Stage2TableAttrs;
            fn resolve_leaf(config: &Cfg, _: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                G::encode_shareability(config, attrs.controls.shareability)?;
                $resolve64::<P, Cfg>(config, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> { resolve_vmsa64_stage2_table(attrs) }
            fn decode_leaf(config: &Cfg, _: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> {
                let mut attrs = $decode64::<P, Cfg>(config, raw)?;
                G::decode_shareability(config, &mut attrs.controls.shareability)?;
                Ok(attrs)
            }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> { decode_vmsa64_stage2_table(raw) }
        }

        impl<P, G, Cfg> AttributeCodec<Vmsa128, $regime<P>, G, Cfg> for VmsaAttributeCodec
        where
            P: Stage2PermissionModel,
            G: TranslationGranule,
            Cfg: Stage2MemoryConfig + Stage2PermissionConfig $(+ $extra)*,
        {
            type SemanticLeaf = SemanticStage2LeafAttrs<Stage2Permission, $pas, SemanticVmsa128Stage2LeafControls>;
            type SemanticTable = SemanticVmsa128Stage2TableAttrs;
            type RawLeaf = RawVmsa128Stage2LeafAttrs;
            type RawTable = RawVmsa128Stage2TableAttrs;
            fn resolve_leaf(config: &Cfg, level: Level, attrs: Self::SemanticLeaf) -> Result<Self::RawLeaf, AttrError> {
                $resolve128::<Cfg>(config, level, attrs)
            }
            fn resolve_table(_: &Cfg, _: Level, attrs: Self::SemanticTable) -> Result<Self::RawTable, AttrError> { resolve_vmsa128_stage2_table(attrs) }
            fn decode_leaf(config: &Cfg, level: Level, raw: Self::RawLeaf) -> Result<Self::SemanticLeaf, AttrError> {
                let attrs = $decode128::<Cfg>(config, raw)?;
                if attrs.controls.bbm_nt && level == Level::L3 {
                    return Err(AttrError::InvalidD128Configuration);
                }
                Ok(attrs)
            }
            fn decode_table(_: &Cfg, _: Level, raw: Self::RawTable) -> Result<Self::SemanticTable, AttrError> { decode_vmsa128_stage2_table(raw) }
        }
    };
}

impl_stage2_codecs!(
    NonSecureEl2Stage2,
    (),
    resolve_vmsa64_stage2_leaf_fixed,
    decode_vmsa64_stage2_leaf_fixed,
    resolve_vmsa128_stage2_leaf_fixed,
    decode_vmsa128_stage2_leaf_fixed,
    []
);
impl_stage2_codecs!(
    SecureEl2SecureIpaStage2,
    SecureSelectablePa,
    resolve_vmsa64_stage2_leaf_secure,
    decode_vmsa64_stage2_leaf_secure,
    resolve_vmsa128_stage2_leaf_secure,
    decode_vmsa128_stage2_leaf_secure,
    [PasConfig<Pas = SecureSelectablePa>]
);
impl_stage2_codecs!(
    SecureEl2NonSecureIpaStage2,
    SecureSelectablePa,
    resolve_vmsa64_stage2_leaf_secure,
    decode_vmsa64_stage2_leaf_secure,
    resolve_vmsa128_stage2_leaf_secure,
    decode_vmsa128_stage2_leaf_secure,
    [PasConfig<Pas = SecureSelectablePa>]
);
impl_stage2_codecs!(
    RealmEl2Stage2,
    RealmOrNonSecurePa,
    resolve_vmsa64_stage2_leaf_realm,
    decode_vmsa64_stage2_leaf_realm,
    resolve_vmsa128_stage2_leaf_realm,
    decode_vmsa128_stage2_leaf_realm,
    []
);
