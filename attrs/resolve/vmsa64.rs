use crate::address::{Granule4KiB, Granule16KiB, Granule64KiB, Level, TranslationGranule};
use crate::attrs::{
    AttrError, FourBit, RawShareability, RawVmsa64Stage1LeafAttrs, RawVmsa64Stage1TableAttrs,
    RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs, ResolvedStage1LeafAttrs,
    ResolvedStage1TableAttrs, ResolvedStage2LeafAttrs, SemanticLeafAttrs, SemanticStage1LeafAttrs,
    SemanticStage1TableAttrs, SemanticStage2LeafAttrs, SemanticTableAttrs,
    SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
    SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
    SoftwareMetadata, Stage2LeafPermissions, Stage2PasContext, Stage2PermissionModel, ThreeBit,
};
use crate::descriptor::{Vmsa64, Vmsa64Lpa2};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolvedVmsa64Stage1LeafControls {
    pub shareability: RawShareability,
    pub access_flag: bool,
    pub alias_bit: bool,
    pub dirty_bit_modifier: bool,
    pub contiguous: bool,
    pub guarded: bool,
    pub software: FourBit,
}

type ResolvedVmsa64Stage1LeafAttrs = ResolvedStage1LeafAttrs<
    ThreeBit,
    RawStage1DirectLeafPermissions,
    RawStage1LeafPas,
    ResolvedVmsa64Stage1LeafControls,
>;

fn resolve_vmsa64_stage1_leaf_resolved<P, A, C>(
    config: &C,
    attrs: SemanticStage1LeafAttrs<
        P::LeafPermissions,
        A::LeafAttr,
        SemanticVmsa64Stage1LeafControls,
    >,
) -> Result<ResolvedVmsa64Stage1LeafAttrs, AttrError>
where
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
    C: Stage1MemoryConfig,
{
    let memory = Vmsa64Stage1Memory::resolve(config, attrs.memory)?;
    let permissions = P::encode_leaf(attrs.permissions)?;
    let pas = A::resolve_leaf(attrs.pas)?;
    let alias_bit = resolve_stage1_alias::<P, A>(attrs.controls.global, pas)?;

    Ok(ResolvedStage1LeafAttrs {
        memory,
        permissions,
        pas,
        controls: ResolvedVmsa64Stage1LeafControls {
            shareability: RawShareability::from_bits(attrs.controls.shareability as u8)?,
            access_flag: attrs.controls.access_flag,
            alias_bit,
            dirty_bit_modifier: matches!(
                attrs.controls.dirty_management,
                crate::attrs::DirtyBitManagement::HardwareManaged
            ),
            contiguous: attrs.controls.contiguous,
            guarded: attrs.controls.guarded,
            software: software_four(attrs.controls.software)?,
        },
    })
}

const fn raw_vmsa64_stage1_leaf(
    resolved: ResolvedVmsa64Stage1LeafAttrs,
) -> RawVmsa64Stage1LeafAttrs {
    RawVmsa64Stage1LeafAttrs {
        attr_index: resolved.memory,
        ns: resolved.pas.ns,
        ap: resolved.permissions.ap,
        shareability: resolved.controls.shareability,
        access_flag: resolved.controls.access_flag,
        alias_bit: resolved.controls.alias_bit,
        dirty_bit_modifier: resolved.controls.dirty_bit_modifier,
        contiguous: resolved.controls.contiguous,
        privileged_execute_never: resolved.permissions.privileged_execute_never,
        unprivileged_execute_never: resolved.permissions.unprivileged_execute_never,
        guarded: resolved.controls.guarded,
        software: resolved.controls.software,
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
    resolve_vmsa64_stage1_leaf_resolved::<P, A, C>(config, attrs).map(raw_vmsa64_stage1_leaf)
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
    let (nse, global) = decode_stage1_alias::<P, A>(raw.alias_bit)?;
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

type ResolvedVmsa64Stage1TableAttrs =
    ResolvedStage1TableAttrs<RawStage1TablePermissionLimits, bool, FourBit>;

fn resolve_vmsa64_stage1_table_resolved<P, A>(
    attrs: SemanticStage1TableAttrs<
        P::TablePermissionLimits,
        A::TableAttr,
        SemanticVmsa64Stage1TableControls,
    >,
) -> Result<ResolvedVmsa64Stage1TableAttrs, AttrError>
where
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
{
    let ns_table = A::resolve_table(attrs.pas)?;
    debug_assert_eq!(ns_table.is_some(), A::USES_NSTABLE);
    Ok(ResolvedStage1TableAttrs {
        permission_limits: P::encode_table(attrs.permission_limits)?,
        pas: ns_table.unwrap_or(false),
        controls: software_four(attrs.controls.software)?,
    })
}

const fn raw_vmsa64_stage1_table(
    resolved: ResolvedVmsa64Stage1TableAttrs,
) -> RawVmsa64Stage1TableAttrs {
    RawVmsa64Stage1TableAttrs {
        privileged_execute_never_limit: resolved.permission_limits.privileged_execute_never_limit,
        unprivileged_execute_never_limit: resolved
            .permission_limits
            .unprivileged_execute_never_limit,
        ap_table: resolved.permission_limits.ap_table,
        ns_table: resolved.pas,
        software: resolved.controls,
    }
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
    resolve_vmsa64_stage1_table_resolved::<P, A>(attrs).map(raw_vmsa64_stage1_table)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolvedVmsa64Stage2LeafControls {
    pub shareability: RawShareability,
    pub access_flag: bool,
    pub dirty_bit_modifier: bool,
    pub contiguous: bool,
    pub software: FourBit,
}

type ResolvedVmsa64Stage2LeafAttrs = ResolvedStage2LeafAttrs<
    FourBit,
    (crate::attrs::Stage2Ap, crate::attrs::Stage2ExecuteNever),
    bool,
    ResolvedVmsa64Stage2LeafControls,
>;

fn resolve_vmsa64_stage2_leaf_resolved<P, A, C>(
    config: &C,
    attrs: SemanticStage2LeafAttrs<
        Stage2LeafPermissions,
        A::OutputAddressSpaceAttr,
        SemanticVmsa64Stage2LeafControls,
    >,
) -> Result<ResolvedVmsa64Stage2LeafAttrs, AttrError>
where
    P: Stage2PermissionModel,
    A: Stage2PasContext + Stage2PasResolver<Vmsa64, C, Software = FourBit>,
    C: Stage2MemoryConfig,
{
    let mut software = software_four(attrs.controls.software)?;
    let descriptor_ns = A::resolve(config, attrs.output_address_space, &mut software)?;
    resolve_vmsa64_stage2_leaf_inner::<P, C>(
        config,
        attrs.memory,
        attrs.permissions,
        descriptor_ns,
        attrs.controls,
        software,
    )
}

fn resolve_vmsa64_stage2_leaf_inner<P, C>(
    config: &C,
    memory: crate::attrs::Stage2MemoryAttributes,
    permissions: Stage2LeafPermissions,
    descriptor_ns: bool,
    controls: SemanticVmsa64Stage2LeafControls,
    software: FourBit,
) -> Result<ResolvedVmsa64Stage2LeafAttrs, AttrError>
where
    P: Stage2PermissionModel,
    C: Stage2MemoryConfig,
{
    Ok(ResolvedStage2LeafAttrs {
        memory: resolve_stage2_memory(config, memory)?,
        permissions: encode_stage2_direct_permissions(permissions, P::XNX)?,
        output_address_space: descriptor_ns,
        controls: ResolvedVmsa64Stage2LeafControls {
            shareability: RawShareability::from_bits(controls.shareability as u8)?,
            access_flag: controls.access_flag,
            dirty_bit_modifier: matches!(
                controls.dirty_management,
                crate::attrs::DirtyBitManagement::HardwareManaged
            ),
            contiguous: controls.contiguous,
            software,
        },
    })
}

const fn raw_vmsa64_stage2_leaf(
    resolved: ResolvedVmsa64Stage2LeafAttrs,
) -> RawVmsa64Stage2LeafAttrs {
    RawVmsa64Stage2LeafAttrs {
        mem_attr: resolved.memory,
        access: resolved.permissions.0,
        shareability: resolved.controls.shareability,
        access_flag: resolved.controls.access_flag,
        dirty_bit_modifier: resolved.controls.dirty_bit_modifier,
        contiguous: resolved.controls.contiguous,
        execute_never: resolved.permissions.1,
        software: resolved.controls.software,
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
    resolve_vmsa64_stage2_leaf_resolved::<P, A, C>(config, attrs).map(raw_vmsa64_stage2_leaf)
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
        controls: decode_vmsa64_stage2_controls(raw, software)?,
    })
}

fn decode_vmsa64_stage2_controls(
    raw: RawVmsa64Stage2LeafAttrs,
    software: FourBit,
) -> Result<SemanticVmsa64Stage2LeafControls, AttrError> {
    Ok(SemanticVmsa64Stage2LeafControls {
        shareability: decode_shareability(raw.shareability)?,
        access_flag: raw.access_flag,
        dirty_management: if raw.dirty_bit_modifier {
            crate::attrs::DirtyBitManagement::HardwareManaged
        } else {
            crate::attrs::DirtyBitManagement::SoftwareManaged
        },
        contiguous: raw.contiguous,
        software: SoftwareMetadata::new(software.bits().into()),
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

fn resolve_stage1_alias<P, A>(global: bool, pas: RawStage1LeafPas) -> Result<bool, AttrError>
where
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
{
    if A::USES_NSE {
        if !global {
            return Err(AttrError::ConflictingSemanticAttributes);
        }
        Ok(pas.nse)
    } else if P::SUPPORTS_EL0 {
        if pas.nse {
            return Err(AttrError::InvalidOutputAddressSpace);
        }
        Ok(!global)
    } else if global && !pas.nse {
        Ok(false)
    } else {
        Err(AttrError::ConflictingSemanticAttributes)
    }
}

fn decode_stage1_alias<P, A>(alias: bool) -> Result<(bool, bool), AttrError>
where
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
{
    if A::USES_NSE {
        Ok((alias, true))
    } else if P::SUPPORTS_EL0 {
        Ok((false, !alias))
    } else if alias {
        Err(AttrError::ConflictingSemanticAttributes)
    } else {
        Ok((false, true))
    }
}

fn software_four(metadata: SoftwareMetadata) -> Result<FourBit, AttrError> {
    if metadata.value() > 0xf {
        Err(AttrError::RawFieldOutOfRange)
    } else {
        FourBit::new(metadata.value() as u8)
    }
}
