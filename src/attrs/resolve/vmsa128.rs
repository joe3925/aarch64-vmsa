use crate::address::{Level, TranslationGranule};
use crate::attrs::SemanticAttributeTypes;
use crate::attrs::{
    AttrError, D128AliasConfig, D128Stage1AliasKind, PrivilegeModel, RawShareability,
    RawVmsa128Stage1LeafAttrs, RawVmsa128Stage1TableAttrs, RawVmsa128Stage2LeafAttrs,
    RawVmsa128Stage2TableAttrs, SemanticLeafAttrs, SemanticStage1LeafAttrs,
    SemanticStage2LeafAttrs, SemanticTableAttrs, SemanticVmsa128Stage1LeafControls,
    SemanticVmsa128Stage1TableAttrs, SemanticVmsa128Stage2LeafControls,
    SemanticVmsa128Stage2TableAttrs, SoftwareMetadata, Stage1EffectivePermissions, Stage1PasModel,
    Stage2PasContext, Stage2Permission, TenBit,
};
use crate::config::format::{DescriptorEndian, Vmsa128};
use crate::descriptor::{DescriptorInterpretation, HasLayout, InterpretsDescriptors};
use crate::regime::{
    HasRegimeLayout, InterpretedLeafFields, InterpretedTableFields, Stage1Regime, Stage2Regime,
};
use crate::translation::{Stage1, Stage2};

use super::codec::AttributeCodecCell;
use super::{
    HasMemoryCodec, MemoryAttributeCodec, RawStage1LeafPas, Stage1MemoryConfig, Stage1PasResolver,
    Stage1PermissionConfig, Stage1PermissionResolver, Stage2MemoryConfig, Stage2PasResolver,
    Stage2PermissionConfig, Stage2PermissionResolver, decode_shareability,
};

impl<E: DescriptorEndian, R, G, Cfg> AttributeCodecCell<Vmsa128<E>, R, G, Cfg> for Stage1
where
    R: Stage1Regime<Stage = Stage1>,
    G: TranslationGranule,
    Cfg: Stage1MemoryConfig + Stage1PermissionConfig + D128AliasConfig,
    R::PasModel: Stage1PasResolver,
    R::DescriptorInterpretation: InterpretsDescriptors<
            Vmsa128<E>,
            Stage1,
            G,
            Layout = <Vmsa128<E> as HasLayout<Stage1, G>>::Layout,
        >,
    Vmsa128<E>: HasRegimeLayout<R, G, Layout = <Vmsa128<E> as HasLayout<Stage1, G>>::Layout>
        + SemanticAttributeTypes<
            Stage1,
            R,
            Leaf = SemanticStage1LeafAttrs<
                Stage1EffectivePermissions,
                <R::PasModel as Stage1PasModel>::LeafAttr,
                SemanticVmsa128Stage1LeafControls,
            >,
            Table = SemanticVmsa128Stage1TableAttrs<<R::PasModel as Stage1PasModel>::TableAttr>,
        >,
{
    fn encode_leaf(
        config: &Cfg,
        level: Level,
        attrs: SemanticLeafAttrs<Vmsa128<E>, R>,
    ) -> Result<InterpretedLeafFields<Vmsa128<E>, R, G>, AttrError> {
        require_stage1_permission_semantics::<R::DescriptorInterpretation, _>(config)?;
        require_nt(level, attrs.controls.bbm_nt)?;
        let pas = R::PasModel::resolve_leaf(attrs.pas)?;
        let alias_bit = if R::PasModel::USES_NSE {
            if config.d128_stage1_alias_kind() != D128Stage1AliasKind::NonSecureExtension
                || !attrs.controls.global
            {
                return Err(AttrError::InvalidD128Alias);
            }
            pas.nse
        } else if R::PrivilegeModel::SUPPORTS_EL0 {
            if config.d128_stage1_alias_kind() != D128Stage1AliasKind::NonGlobal || pas.nse {
                return Err(AttrError::InvalidD128Alias);
            }
            !attrs.controls.global
        } else if attrs.controls.global && !pas.nse {
            false
        } else {
            return Err(AttrError::InvalidD128Alias);
        };
        let attr_index =
            <Vmsa128<E> as HasMemoryCodec<Stage1>>::Codec::encode(config, attrs.memory)?;
        let permissions = Stage1PermissionResolver::new(config).resolve(attrs.permissions)?;
        let shareability = RawShareability::from_bits(attrs.controls.shareability as u8)?;
        let software = software_ten(attrs.controls.software)?;

        Ok(RawVmsa128Stage1LeafAttrs {
            attr_index,
            bbm_nt: attrs.controls.bbm_nt,
            not_dirty: attrs.controls.dirty_state.into(),
            shareability,
            access_flag: attrs.controls.access_flag,
            alias_bit,
            contiguous: attrs.controls.contiguous,
            guarded: attrs.controls.guarded,
            protected: attrs.controls.protected,
            permissions,
            ns: pas.ns,
            software,
        })
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa128<E>, R>,
    ) -> Result<InterpretedTableFields<Vmsa128<E>, R, G>, AttrError> {
        let ns_table = R::PasModel::resolve_table(attrs.pas)?;
        debug_assert_eq!(ns_table.is_some(), R::PasModel::USES_NSTABLE);
        Ok(RawVmsa128Stage1TableAttrs {
            table_nt: attrs.table_nt,
            access_flag: attrs.access_flag,
            disch: attrs.disch,
            protected: attrs.protected,
            ns_table: ns_table.unwrap_or(false),
            software: software_ten(attrs.software)?,
        })
    }

    fn decode_leaf(
        config: &Cfg,
        level: Level,
        raw: InterpretedLeafFields<Vmsa128<E>, R, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa128<E>, R>, AttrError> {
        require_stage1_permission_semantics::<R::DescriptorInterpretation, _>(config)?;
        require_nt(level, raw.bbm_nt)?;
        let (nse, global) = if R::PasModel::USES_NSE {
            if config.d128_stage1_alias_kind() != D128Stage1AliasKind::NonSecureExtension {
                return Err(AttrError::InvalidD128Alias);
            }
            (raw.alias_bit, true)
        } else if R::PrivilegeModel::SUPPORTS_EL0 {
            if config.d128_stage1_alias_kind() != D128Stage1AliasKind::NonGlobal {
                return Err(AttrError::InvalidD128Alias);
            }
            (false, !raw.alias_bit)
        } else if raw.alias_bit {
            return Err(AttrError::InvalidD128Alias);
        } else {
            (false, true)
        };

        Ok(SemanticStage1LeafAttrs {
            memory: <Vmsa128<E> as HasMemoryCodec<Stage1>>::Codec::decode(config, raw.attr_index)?,
            permissions: Stage1PermissionResolver::new(config).decode(raw.permissions)?,
            pas: R::PasModel::decode_leaf(RawStage1LeafPas { ns: raw.ns, nse })?,
            controls: SemanticVmsa128Stage1LeafControls {
                bbm_nt: raw.bbm_nt,
                dirty_state: raw.not_dirty.into(),
                shareability: decode_shareability(raw.shareability)?,
                access_flag: raw.access_flag,
                global,
                contiguous: raw.contiguous,
                guarded: raw.guarded,
                protected: raw.protected,
                software: SoftwareMetadata::new(raw.software.bits()),
            },
        })
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: InterpretedTableFields<Vmsa128<E>, R, G>,
    ) -> Result<SemanticTableAttrs<Vmsa128<E>, R>, AttrError> {
        Ok(SemanticVmsa128Stage1TableAttrs {
            table_nt: raw.table_nt,
            access_flag: raw.access_flag,
            disch: raw.disch,
            protected: raw.protected,
            pas: R::PasModel::decode_table(raw.ns_table)?,
            software: SoftwareMetadata::new(raw.software.bits()),
        })
    }
}

impl<E: DescriptorEndian, R, G, Cfg> AttributeCodecCell<Vmsa128<E>, R, G, Cfg> for Stage2
where
    R: Stage2Regime<Stage = Stage2>,
    G: TranslationGranule,
    Cfg: Stage2MemoryConfig + Stage2PermissionConfig,
    R::PasModel: Stage2PasContext + Stage2PasResolver<Vmsa128<E>, Cfg, Software = TenBit>,
    R::DescriptorInterpretation: InterpretsDescriptors<
            Vmsa128<E>,
            Stage2,
            G,
            Layout = <Vmsa128<E> as HasLayout<Stage2, G>>::Layout,
        >,
    Vmsa128<E>: HasRegimeLayout<R, G, Layout = <Vmsa128<E> as HasLayout<Stage2, G>>::Layout>
        + SemanticAttributeTypes<
            Stage2,
            R,
            Leaf = SemanticStage2LeafAttrs<
                Stage2Permission,
                <R::PasModel as Stage2PasContext>::OutputAddressSpaceAttr,
                SemanticVmsa128Stage2LeafControls,
            >,
            Table = SemanticVmsa128Stage2TableAttrs,
        >,
{
    fn encode_leaf(
        config: &Cfg,
        level: Level,
        attrs: SemanticLeafAttrs<Vmsa128<E>, R>,
    ) -> Result<InterpretedLeafFields<Vmsa128<E>, R, G>, AttrError> {
        let mut software = software_ten(attrs.controls.software)?;
        let ns = R::PasModel::resolve(config, attrs.output_address_space, &mut software)?;
        require_nt(level, attrs.controls.bbm_nt)?;
        let mem_attr = <Vmsa128<E> as HasMemoryCodec<Stage2>>::Codec::encode(config, attrs.memory)?;
        let permissions = Stage2PermissionResolver::new(config).resolve(attrs.permissions)?;
        let shareability = RawShareability::from_bits(attrs.controls.shareability as u8)?;
        Ok(RawVmsa128Stage2LeafAttrs {
            mem_attr,
            bbm_nt: attrs.controls.bbm_nt,
            dirty: attrs.controls.dirty_state.into(),
            shareability,
            access_flag: attrs.controls.access_flag,
            force_no_execute: attrs.controls.force_no_execute,
            contiguous: attrs.controls.contiguous,
            assured_only: attrs.controls.assured_only,
            permissions,
            ns,
            software,
        })
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa128<E>, R>,
    ) -> Result<InterpretedTableFields<Vmsa128<E>, R, G>, AttrError> {
        Ok(RawVmsa128Stage2TableAttrs {
            table_nt: attrs.table_nt,
            access_flag: attrs.access_flag,
            software: software_ten(attrs.software)?,
        })
    }

    fn decode_leaf(
        config: &Cfg,
        level: Level,
        raw: InterpretedLeafFields<Vmsa128<E>, R, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa128<E>, R>, AttrError> {
        require_nt(level, raw.bbm_nt)?;
        let mut software = raw.software;
        let output_address_space = R::PasModel::decode(config, raw.ns, &mut software)?;
        Ok(SemanticStage2LeafAttrs {
            memory: <Vmsa128<E> as HasMemoryCodec<Stage2>>::Codec::decode(config, raw.mem_attr)?,
            permissions: Stage2PermissionResolver::new(config).decode(raw.permissions)?,
            output_address_space,
            controls: SemanticVmsa128Stage2LeafControls {
                bbm_nt: raw.bbm_nt,
                dirty_state: raw.dirty.into(),
                shareability: decode_shareability(raw.shareability)?,
                access_flag: raw.access_flag,
                force_no_execute: raw.force_no_execute,
                contiguous: raw.contiguous,
                assured_only: raw.assured_only,
                software: SoftwareMetadata::new(software.bits()),
            },
        })
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: InterpretedTableFields<Vmsa128<E>, R, G>,
    ) -> Result<SemanticTableAttrs<Vmsa128<E>, R>, AttrError> {
        Ok(SemanticVmsa128Stage2TableAttrs {
            table_nt: raw.table_nt,
            access_flag: raw.access_flag,
            software: SoftwareMetadata::new(raw.software.bits()),
        })
    }
}

fn require_nt(level: Level, nt: bool) -> Result<(), AttrError> {
    if nt && level == Level::L3 {
        Err(AttrError::InvalidD128Configuration)
    } else {
        Ok(())
    }
}

fn software_ten(metadata: SoftwareMetadata) -> Result<TenBit, AttrError> {
    TenBit::new(metadata.value())
}

fn require_stage1_permission_semantics<I, C>(config: &C) -> Result<(), AttrError>
where
    I: DescriptorInterpretation,
    C: Stage1PermissionConfig,
{
    let settings = config.stage1_permissions();
    if (!I::SUPPORTS_STAGE1_PERMISSION_INDIRECTION
        && !matches!(settings.base, super::Stage1BasePermissions::Direct))
        || (!I::SUPPORTS_STAGE1_PERMISSION_OVERLAYS
            && (settings.overlays.privileged.is_some() || settings.overlays.unprivileged.is_some()))
    {
        Err(AttrError::PermissionModeMismatch)
    } else {
        Ok(())
    }
}
