use crate::address::{Granule4KiB, Granule16KiB, Granule64KiB, Level, TranslationGranule};
use crate::attrs::{
    AttrError, D128AliasConfig, FourBit, SemanticAttributeTypes, SemanticLeafAttrs,
    SemanticTableAttrs, Shareability, ShareabilityConfig, Stage1MemoryConfig,
    Stage1PermissionConfig, Stage2MemoryConfig, Stage2PasContext, Stage2PermissionConfig, TenBit,
};
use crate::descriptor::{DescriptorFormat, HasLayout, Vmsa64, Vmsa64Lpa2, Vmsa128};
use crate::regime::*;
use crate::translation::{Stage1, Stage2, TranslationStage};

use super::*;
pub trait AttributeCodec<R, G, Cfg, S = <R as TranslationRegime>::Stage>:
    DescriptorFormat + HasLayout<S, G> + SemanticAttributeTypes<S, R>
where
    S: TranslationStage,
    R: TranslationRegime<Stage = S>,
    G: TranslationGranule,
{
    fn encode_leaf(
        config: &Cfg,
        level: Level,
        attrs: SemanticLeafAttrs<Self, R>,
    ) -> Result<RegimeLeafFields<Self, R, G>, AttrError>;

    fn encode_table(
        config: &Cfg,
        level: Level,
        attrs: SemanticTableAttrs<Self, R>,
    ) -> Result<RegimeTableFields<Self, R, G>, AttrError>;

    fn decode_leaf(
        config: &Cfg,
        level: Level,
        raw: RegimeLeafFields<Self, R, G>,
    ) -> Result<SemanticLeafAttrs<Self, R>, AttrError>;

    fn decode_table(
        config: &Cfg,
        level: Level,
        raw: RegimeTableFields<Self, R, G>,
    ) -> Result<SemanticTableAttrs<Self, R>, AttrError>;
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
        impl<R, G, Cfg> AttributeCodec<R, G, Cfg, Stage1> for Vmsa64
        where
            R: Stage1Regime<Stage = Stage1>,
            G: TranslationGranule,
            Cfg: Stage1MemoryConfig,
            R::PrivilegeModel: Stage1DirectPermissionModel,
            R::PasModel: Stage1PasResolver,
        {
            fn encode_leaf(
                config: &Cfg,
                _: Level,
                attrs: SemanticLeafAttrs<Self, R>,
            ) -> Result<RegimeLeafFields<Self, R, G>, AttrError> {
                resolve_vmsa64_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(config, attrs)
            }
            fn encode_table(
                _: &Cfg,
                _: Level,
                attrs: SemanticTableAttrs<Self, R>,
            ) -> Result<RegimeTableFields<Self, R, G>, AttrError> {
                resolve_vmsa64_stage1_table::<R::PrivilegeModel, R::PasModel>(attrs)
            }
            fn decode_leaf(
                config: &Cfg,
                _: Level,
                raw: RegimeLeafFields<Self, R, G>,
            ) -> Result<SemanticLeafAttrs<Self, R>, AttrError> {
                decode_vmsa64_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(config, raw)
            }
            fn decode_table(
                _: &Cfg,
                _: Level,
                raw: RegimeTableFields<Self, R, G>,
            ) -> Result<SemanticTableAttrs<Self, R>, AttrError> {
                decode_vmsa64_stage1_table::<R::PrivilegeModel, R::PasModel>(raw)
            }
        }

        impl<R, G, Cfg> AttributeCodec<R, G, Cfg, Stage1> for Vmsa64Lpa2
        where
            R: Stage1Regime<Stage = Stage1>,
            G: TranslationGranule + Lpa2GranulePolicy<Cfg>,
            Cfg: Stage1MemoryConfig + ShareabilityConfig,
            R::PrivilegeModel: Stage1DirectPermissionModel,
            R::PasModel: Stage1PasResolver,
        {
            fn encode_leaf(
                config: &Cfg,
                _: Level,
                attrs: SemanticLeafAttrs<Self, R>,
            ) -> Result<RegimeLeafFields<Self, R, G>, AttrError> {
                G::encode_shareability(config, attrs.controls.shareability)?;
                resolve_vmsa64_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(config, attrs)
            }
            fn encode_table(
                _: &Cfg,
                _: Level,
                attrs: SemanticTableAttrs<Self, R>,
            ) -> Result<RegimeTableFields<Self, R, G>, AttrError> {
                resolve_vmsa64_stage1_table::<R::PrivilegeModel, R::PasModel>(attrs)
            }
            fn decode_leaf(
                config: &Cfg,
                _: Level,
                raw: RegimeLeafFields<Self, R, G>,
            ) -> Result<SemanticLeafAttrs<Self, R>, AttrError> {
                let mut attrs =
                    decode_vmsa64_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(config, raw)?;
                G::decode_shareability(config, &mut attrs.controls.shareability)?;
                Ok(attrs)
            }
            fn decode_table(
                _: &Cfg,
                _: Level,
                raw: RegimeTableFields<Self, R, G>,
            ) -> Result<SemanticTableAttrs<Self, R>, AttrError> {
                decode_vmsa64_stage1_table::<R::PrivilegeModel, R::PasModel>(raw)
            }
        }

        impl<R, G, Cfg> AttributeCodec<R, G, Cfg, Stage1> for Vmsa128
        where
            R: Stage1Regime<Stage = Stage1>,
            G: TranslationGranule,
            Cfg: Stage1MemoryConfig + Stage1PermissionConfig + D128AliasConfig,
            R::PasModel: Stage1PasResolver,
        {
            fn encode_leaf(
                config: &Cfg,
                level: Level,
                attrs: SemanticLeafAttrs<Self, R>,
            ) -> Result<RegimeLeafFields<Self, R, G>, AttrError> {
                resolve_vmsa128_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(
                    config, level, attrs,
                )
            }
            fn encode_table(
                _: &Cfg,
                _: Level,
                attrs: SemanticTableAttrs<Self, R>,
            ) -> Result<RegimeTableFields<Self, R, G>, AttrError> {
                resolve_vmsa128_stage1_table::<R::PasModel>(attrs)
            }
            fn decode_leaf(
                config: &Cfg,
                level: Level,
                raw: RegimeLeafFields<Self, R, G>,
            ) -> Result<SemanticLeafAttrs<Self, R>, AttrError> {
                decode_vmsa128_stage1_leaf::<R::PrivilegeModel, R::PasModel, Cfg>(
                    config, level, raw,
                )
            }
            fn decode_table(
                _: &Cfg,
                _: Level,
                raw: RegimeTableFields<Self, R, G>,
            ) -> Result<SemanticTableAttrs<Self, R>, AttrError> {
                decode_vmsa128_stage1_table::<R::PasModel>(raw)
            }
        }
    };
}

impl_stage1_codecs!();

impl<R, G, Cfg> AttributeCodec<R, G, Cfg, Stage2> for Vmsa64
where
    R: Stage2Regime<Stage = Stage2>,
    G: TranslationGranule,
    Cfg: Stage2MemoryConfig,
    R::PasModel: Stage2PasContext + Stage2PasResolver<Vmsa64, Cfg, Software = FourBit>,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Self, R>,
    ) -> Result<RegimeLeafFields<Self, R, G>, AttrError> {
        resolve_vmsa64_stage2_leaf::<R::PermissionModel, R::PasModel, Cfg>(config, attrs)
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Self, R>,
    ) -> Result<RegimeTableFields<Self, R, G>, AttrError> {
        resolve_vmsa64_stage2_table(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: RegimeLeafFields<Self, R, G>,
    ) -> Result<SemanticLeafAttrs<Self, R>, AttrError> {
        decode_vmsa64_stage2_leaf::<R::PermissionModel, R::PasModel, Cfg>(config, raw)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: RegimeTableFields<Self, R, G>,
    ) -> Result<SemanticTableAttrs<Self, R>, AttrError> {
        decode_vmsa64_stage2_table(raw)
    }
}

impl<R, G, Cfg> AttributeCodec<R, G, Cfg, Stage2> for Vmsa64Lpa2
where
    R: Stage2Regime<Stage = Stage2>,
    G: TranslationGranule + Lpa2GranulePolicy<Cfg>,
    Cfg: Stage2MemoryConfig + ShareabilityConfig,
    R::PasModel: Stage2PasContext + Stage2PasResolver<Vmsa64, Cfg, Software = FourBit>,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Self, R>,
    ) -> Result<RegimeLeafFields<Self, R, G>, AttrError> {
        G::encode_shareability(config, attrs.controls.shareability)?;
        resolve_vmsa64_stage2_leaf::<R::PermissionModel, R::PasModel, Cfg>(config, attrs)
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Self, R>,
    ) -> Result<RegimeTableFields<Self, R, G>, AttrError> {
        resolve_vmsa64_stage2_table(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: RegimeLeafFields<Self, R, G>,
    ) -> Result<SemanticLeafAttrs<Self, R>, AttrError> {
        let mut attrs =
            decode_vmsa64_stage2_leaf::<R::PermissionModel, R::PasModel, Cfg>(config, raw)?;
        G::decode_shareability(config, &mut attrs.controls.shareability)?;
        Ok(attrs)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: RegimeTableFields<Self, R, G>,
    ) -> Result<SemanticTableAttrs<Self, R>, AttrError> {
        decode_vmsa64_stage2_table(raw)
    }
}

impl<R, G, Cfg> AttributeCodec<R, G, Cfg, Stage2> for Vmsa128
where
    R: Stage2Regime<Stage = Stage2>,
    G: TranslationGranule,
    Cfg: Stage2MemoryConfig + Stage2PermissionConfig,
    R::PasModel: Stage2PasContext + Stage2PasResolver<Vmsa128, Cfg, Software = TenBit>,
{
    fn encode_leaf(
        config: &Cfg,
        level: Level,
        attrs: SemanticLeafAttrs<Self, R>,
    ) -> Result<RegimeLeafFields<Self, R, G>, AttrError> {
        resolve_vmsa128_stage2_leaf::<R::PasModel, Cfg>(config, level, attrs)
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Self, R>,
    ) -> Result<RegimeTableFields<Self, R, G>, AttrError> {
        resolve_vmsa128_stage2_table(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        level: Level,
        raw: RegimeLeafFields<Self, R, G>,
    ) -> Result<SemanticLeafAttrs<Self, R>, AttrError> {
        decode_vmsa128_stage2_leaf::<R::PasModel, Cfg>(config, level, raw)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: RegimeTableFields<Self, R, G>,
    ) -> Result<SemanticTableAttrs<Self, R>, AttrError> {
        decode_vmsa128_stage2_table(raw)
    }
}
