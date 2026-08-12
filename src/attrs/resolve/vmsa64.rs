use crate::address::{Level, TranslationGranule};
use crate::attrs::{
    AttrError, FourBit, RawShareability, RawVmsa64Stage1LeafAttrs, RawVmsa64Stage1TableAttrs,
    RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs, SemanticLeafAttrs,
    SemanticStage1LeafAttrs, SemanticStage1TableAttrs, SemanticStage2LeafAttrs, SemanticTableAttrs,
    SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
    SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
    SoftwareMetadata, Stage2LeafPermissions, Stage2PasContext, Stage2PermissionModel,
};
use crate::config::format::{Vmsa64, Vmsa64Lpa2};
use crate::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
use crate::regime::{RegimeLeafFields, RegimeTableFields, Stage1Regime, Stage2Regime};
use crate::translation::{Stage1, Stage2};

use super::codec::AttributeCodecCell;
use super::{
    RawStage1DirectLeafPermissions, RawStage1LeafPas, RawStage1TablePermissionLimits,
    ShareabilityConfig, Stage1DirectPermissionModel, Stage1MemoryConfig, Stage1MemoryResolver,
    Stage1PasResolver, Stage2MemoryConfig, Stage2PasResolver, Vmsa64Stage1Memory,
    decode_shareability, decode_stage2_direct_permissions, decode_stage2_memory,
    encode_stage2_direct_permissions, require_effective_shareability, resolve_stage2_memory,
};

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

fn encode_stage1_leaf_core<P, A, C>(
    config: &C,
    attrs: SemanticStage1LeafAttrs<
        P::LeafPermissions,
        A::LeafAttr,
        SemanticVmsa64Stage1LeafControls,
    >,
) -> Result<RawVmsa64Stage1LeafAttrs, AttrError>
where
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
    C: Stage1MemoryConfig,
{
    let attr_index = Vmsa64Stage1Memory::resolve(config, attrs.memory)?;
    let permissions = P::encode_leaf(attrs.permissions)?;
    let pas = A::resolve_leaf(attrs.pas)?;
    let alias_bit = if A::USES_NSE {
        if !attrs.controls.global {
            return Err(AttrError::ConflictingSemanticAttributes);
        }
        pas.nse
    } else if P::SUPPORTS_EL0 {
        if pas.nse {
            return Err(AttrError::InvalidOutputAddressSpace);
        }
        !attrs.controls.global
    } else if attrs.controls.global && !pas.nse {
        false
    } else {
        return Err(AttrError::ConflictingSemanticAttributes);
    };

    Ok(RawVmsa64Stage1LeafAttrs {
        attr_index,
        ns: pas.ns,
        ap: permissions.ap,
        shareability: RawShareability::from_bits(attrs.controls.shareability as u8)?,
        access_flag: attrs.controls.access_flag,
        alias_bit,
        dirty_bit_modifier: matches!(
            attrs.controls.dirty_management,
            crate::attrs::DirtyBitManagement::HardwareManaged
        ),
        contiguous: attrs.controls.contiguous,
        privileged_execute_never: permissions.privileged_execute_never,
        unprivileged_execute_never: permissions.unprivileged_execute_never,
        guarded: attrs.controls.guarded,
        software: software_four(attrs.controls.software)?,
    })
}

fn decode_stage1_leaf_core<P, A, C>(
    config: &C,
    raw: RawVmsa64Stage1LeafAttrs,
) -> Result<
    SemanticStage1LeafAttrs<P::LeafPermissions, A::LeafAttr, SemanticVmsa64Stage1LeafControls>,
    AttrError,
>
where
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
    C: Stage1MemoryConfig,
{
    let (nse, global) = if A::USES_NSE {
        (raw.alias_bit, true)
    } else if P::SUPPORTS_EL0 {
        (false, !raw.alias_bit)
    } else if raw.alias_bit {
        return Err(AttrError::ConflictingSemanticAttributes);
    } else {
        (false, true)
    };
    Ok(SemanticStage1LeafAttrs {
        memory: Vmsa64Stage1Memory::decode(config, raw.attr_index)?,
        permissions: P::decode_leaf(RawStage1DirectLeafPermissions {
            ap: raw.ap,
            privileged_execute_never: raw.privileged_execute_never,
            unprivileged_execute_never: raw.unprivileged_execute_never,
        })?,
        pas: A::decode_leaf(RawStage1LeafPas { ns: raw.ns, nse })?,
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: decode_shareability(raw.shareability)?,
            access_flag: raw.access_flag,
            global,
            dirty_management: if raw.dirty_bit_modifier {
                crate::attrs::DirtyBitManagement::HardwareManaged
            } else {
                crate::attrs::DirtyBitManagement::SoftwareManaged
            },
            contiguous: raw.contiguous,
            guarded: raw.guarded,
            software: SoftwareMetadata::new(raw.software.bits().into()),
        },
    })
}

fn encode_stage1_table_core<P, A>(
    attrs: SemanticStage1TableAttrs<
        P::TablePermissionLimits,
        A::TableAttr,
        SemanticVmsa64Stage1TableControls,
    >,
) -> Result<RawVmsa64Stage1TableAttrs, AttrError>
where
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
{
    let ns_table = A::resolve_table(attrs.pas)?;
    debug_assert_eq!(ns_table.is_some(), A::USES_NSTABLE);
    let permission_limits = P::encode_table(attrs.permission_limits)?;
    Ok(RawVmsa64Stage1TableAttrs {
        privileged_execute_never_limit: permission_limits.privileged_execute_never_limit,
        unprivileged_execute_never_limit: permission_limits.unprivileged_execute_never_limit,
        ap_table: permission_limits.ap_table,
        ns_table: ns_table.unwrap_or(false),
        software: software_four(attrs.controls.software)?,
    })
}

fn decode_stage1_table_core<P, A>(
    raw: RawVmsa64Stage1TableAttrs,
) -> Result<
    SemanticStage1TableAttrs<
        P::TablePermissionLimits,
        A::TableAttr,
        SemanticVmsa64Stage1TableControls,
    >,
    AttrError,
>
where
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
{
    Ok(SemanticStage1TableAttrs {
        permission_limits: P::decode_table(RawStage1TablePermissionLimits {
            ap_table: raw.ap_table,
            privileged_execute_never_limit: raw.privileged_execute_never_limit,
            unprivileged_execute_never_limit: raw.unprivileged_execute_never_limit,
        })?,
        pas: A::decode_table(raw.ns_table)?,
        controls: SemanticVmsa64Stage1TableControls {
            software: SoftwareMetadata::new(raw.software.bits().into()),
        },
    })
}

impl<R, G, Cfg> AttributeCodecCell<Vmsa64, R, G, Cfg> for Stage1
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
        attrs: SemanticLeafAttrs<Vmsa64, R>,
    ) -> Result<RegimeLeafFields<Vmsa64, R, G>, AttrError> {
        encode_stage1_leaf_core::<R::PrivilegeModel, R::PasModel, Cfg>(config, attrs)
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa64, R>,
    ) -> Result<RegimeTableFields<Vmsa64, R, G>, AttrError> {
        encode_stage1_table_core::<R::PrivilegeModel, R::PasModel>(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: RegimeLeafFields<Vmsa64, R, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa64, R>, AttrError> {
        decode_stage1_leaf_core::<R::PrivilegeModel, R::PasModel, Cfg>(config, raw)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: RegimeTableFields<Vmsa64, R, G>,
    ) -> Result<SemanticTableAttrs<Vmsa64, R>, AttrError> {
        decode_stage1_table_core::<R::PrivilegeModel, R::PasModel>(raw)
    }
}

impl<R, G, Cfg> AttributeCodecCell<Vmsa64Lpa2, R, G, Cfg> for Stage1
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
        attrs: SemanticLeafAttrs<Vmsa64Lpa2, R>,
    ) -> Result<RegimeLeafFields<Vmsa64Lpa2, R, G>, AttrError> {
        G::encode_shareability(config, attrs.controls.shareability)?;
        encode_stage1_leaf_core::<R::PrivilegeModel, R::PasModel, Cfg>(config, attrs)
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa64Lpa2, R>,
    ) -> Result<RegimeTableFields<Vmsa64Lpa2, R, G>, AttrError> {
        encode_stage1_table_core::<R::PrivilegeModel, R::PasModel>(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: RegimeLeafFields<Vmsa64Lpa2, R, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa64Lpa2, R>, AttrError> {
        let mut attrs =
            decode_stage1_leaf_core::<R::PrivilegeModel, R::PasModel, Cfg>(config, raw)?;
        G::decode_shareability(config, &mut attrs.controls.shareability)?;
        Ok(attrs)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: RegimeTableFields<Vmsa64Lpa2, R, G>,
    ) -> Result<SemanticTableAttrs<Vmsa64Lpa2, R>, AttrError> {
        decode_stage1_table_core::<R::PrivilegeModel, R::PasModel>(raw)
    }
}

fn encode_stage2_leaf_core<P, A, C>(
    config: &C,
    attrs: SemanticStage2LeafAttrs<
        Stage2LeafPermissions,
        A::OutputAddressSpaceAttr,
        SemanticVmsa64Stage2LeafControls,
    >,
) -> Result<RawVmsa64Stage2LeafAttrs, AttrError>
where
    P: Stage2PermissionModel,
    A: Stage2PasContext + Stage2PasResolver<Vmsa64, C, Software = FourBit>,
    C: Stage2MemoryConfig,
{
    let mut software = software_four(attrs.controls.software)?;
    let _descriptor_ns = A::resolve(config, attrs.output_address_space, &mut software)?;
    let mem_attr = resolve_stage2_memory(config, attrs.memory)?;
    let (access, execute_never) = encode_stage2_direct_permissions(attrs.permissions, P::XNX)?;
    Ok(RawVmsa64Stage2LeafAttrs {
        mem_attr,
        access,
        shareability: RawShareability::from_bits(attrs.controls.shareability as u8)?,
        access_flag: attrs.controls.access_flag,
        dirty_bit_modifier: matches!(
            attrs.controls.dirty_management,
            crate::attrs::DirtyBitManagement::HardwareManaged
        ),
        contiguous: attrs.controls.contiguous,
        execute_never,
        software,
    })
}

fn decode_stage2_leaf_core<P, A, C>(
    config: &C,
    raw: RawVmsa64Stage2LeafAttrs,
) -> Result<
    SemanticStage2LeafAttrs<
        Stage2LeafPermissions,
        A::OutputAddressSpaceAttr,
        SemanticVmsa64Stage2LeafControls,
    >,
    AttrError,
>
where
    P: Stage2PermissionModel,
    A: Stage2PasContext + Stage2PasResolver<Vmsa64, C, Software = FourBit>,
    C: Stage2MemoryConfig,
{
    let mut software = raw.software;
    let output_address_space = A::decode(config, false, &mut software)?;
    Ok(SemanticStage2LeafAttrs {
        memory: decode_stage2_memory(config, raw.mem_attr)?,
        permissions: decode_stage2_direct_permissions(raw.access, raw.execute_never, P::XNX)?,
        output_address_space,
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: decode_shareability(raw.shareability)?,
            access_flag: raw.access_flag,
            dirty_management: if raw.dirty_bit_modifier {
                crate::attrs::DirtyBitManagement::HardwareManaged
            } else {
                crate::attrs::DirtyBitManagement::SoftwareManaged
            },
            contiguous: raw.contiguous,
            software: SoftwareMetadata::new(software.bits().into()),
        },
    })
}

fn encode_stage2_table_core(
    attrs: SemanticVmsa64Stage2TableAttrs,
) -> Result<RawVmsa64Stage2TableAttrs, AttrError> {
    Ok(RawVmsa64Stage2TableAttrs {
        software: software_four(attrs.software)?,
    })
}

fn decode_stage2_table_core(
    raw: RawVmsa64Stage2TableAttrs,
) -> Result<SemanticVmsa64Stage2TableAttrs, AttrError> {
    Ok(SemanticVmsa64Stage2TableAttrs {
        software: SoftwareMetadata::new(raw.software.bits().into()),
    })
}

impl<R, G, Cfg> AttributeCodecCell<Vmsa64, R, G, Cfg> for Stage2
where
    R: Stage2Regime<Stage = Stage2>,
    G: TranslationGranule,
    Cfg: Stage2MemoryConfig,
    R::PasModel: Stage2PasContext + Stage2PasResolver<Vmsa64, Cfg, Software = FourBit>,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64, R>,
    ) -> Result<RegimeLeafFields<Vmsa64, R, G>, AttrError> {
        encode_stage2_leaf_core::<R::PermissionModel, R::PasModel, Cfg>(config, attrs)
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa64, R>,
    ) -> Result<RegimeTableFields<Vmsa64, R, G>, AttrError> {
        encode_stage2_table_core(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: RegimeLeafFields<Vmsa64, R, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa64, R>, AttrError> {
        decode_stage2_leaf_core::<R::PermissionModel, R::PasModel, Cfg>(config, raw)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: RegimeTableFields<Vmsa64, R, G>,
    ) -> Result<SemanticTableAttrs<Vmsa64, R>, AttrError> {
        decode_stage2_table_core(raw)
    }
}

impl<R, G, Cfg> AttributeCodecCell<Vmsa64Lpa2, R, G, Cfg> for Stage2
where
    R: Stage2Regime<Stage = Stage2>,
    G: TranslationGranule + Lpa2GranulePolicy<Cfg>,
    Cfg: Stage2MemoryConfig + ShareabilityConfig,
    R::PasModel: Stage2PasContext + Stage2PasResolver<Vmsa64, Cfg, Software = FourBit>,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64Lpa2, R>,
    ) -> Result<RegimeLeafFields<Vmsa64Lpa2, R, G>, AttrError> {
        G::encode_shareability(config, attrs.controls.shareability)?;
        encode_stage2_leaf_core::<R::PermissionModel, R::PasModel, Cfg>(config, attrs)
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa64Lpa2, R>,
    ) -> Result<RegimeTableFields<Vmsa64Lpa2, R, G>, AttrError> {
        encode_stage2_table_core(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: RegimeLeafFields<Vmsa64Lpa2, R, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa64Lpa2, R>, AttrError> {
        let mut attrs =
            decode_stage2_leaf_core::<R::PermissionModel, R::PasModel, Cfg>(config, raw)?;
        G::decode_shareability(config, &mut attrs.controls.shareability)?;
        Ok(attrs)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: RegimeTableFields<Vmsa64Lpa2, R, G>,
    ) -> Result<SemanticTableAttrs<Vmsa64Lpa2, R>, AttrError> {
        decode_stage2_table_core(raw)
    }
}

fn software_four(metadata: SoftwareMetadata) -> Result<FourBit, AttrError> {
    if metadata.value() > 0xf {
        Err(AttrError::RawFieldOutOfRange)
    } else {
        FourBit::new(metadata.value() as u8)
    }
}
