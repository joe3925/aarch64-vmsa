use crate::address::Level;
use crate::attrs::{
    AttrError, D128AliasConfig, D128Stage1AliasKind, FourBit, PasConfig, PermissionIndices,
    PrivilegeModel, RawShareability, RawVmsa128Stage1LeafAttrs, RawVmsa128Stage1TableAttrs,
    RawVmsa128Stage2LeafAttrs, RawVmsa128Stage2TableAttrs, RealmOrNonSecurePa,
    ResolvedStage1LeafAttrs, ResolvedStage2LeafAttrs, SecureSelectablePa, SemanticStage1LeafAttrs,
    SemanticStage2LeafAttrs, SemanticVmsa128Stage1LeafControls, SemanticVmsa128Stage1TableAttrs,
    SemanticVmsa128Stage2LeafControls, SemanticVmsa128Stage2TableAttrs, SoftwareMetadata,
    Stage1EffectivePermissions, Stage1NotDirty, Stage2Dirty, Stage2Permission, TenBit,
};

use super::{
    RawStage1LeafPas, Stage1MemoryConfig, Stage1MemoryResolver, Stage1PasResolver,
    Stage1PermissionConfig, Stage1PermissionResolver, Stage2MemoryConfig, Stage2PermissionConfig,
    Stage2PermissionResolver, Vmsa128Stage1Memory, decode_realm_stage2_pas, decode_shareability,
    decode_stage2_memory, resolve_configured_secure_stage2_pas, resolve_fixed_nonsecure_stage2_pas,
    resolve_realm_stage2_pas, resolve_stage2_memory,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolvedVmsa128Stage1LeafControls {
    pub bbm_nt: bool,
    pub not_dirty: Stage1NotDirty,
    pub shareability: RawShareability,
    pub access_flag: bool,
    pub alias_bit: bool,
    pub contiguous: bool,
    pub guarded: bool,
    pub protected: bool,
    pub software: TenBit,
}

type ResolvedVmsa128Stage1LeafAttrs = ResolvedStage1LeafAttrs<
    FourBit,
    PermissionIndices,
    RawStage1LeafPas,
    ResolvedVmsa128Stage1LeafControls,
>;

fn resolve_vmsa128_stage1_leaf_resolved<P, A, C>(
    config: &C,
    level: Level,
    attrs: SemanticStage1LeafAttrs<
        Stage1EffectivePermissions,
        A::LeafAttr,
        SemanticVmsa128Stage1LeafControls,
    >,
) -> Result<ResolvedVmsa128Stage1LeafAttrs, AttrError>
where
    P: PrivilegeModel,
    A: Stage1PasResolver,
    C: Stage1MemoryConfig + Stage1PermissionConfig + D128AliasConfig,
{
    require_nt(level, attrs.controls.bbm_nt)?;
    let pas = A::resolve_leaf(attrs.pas)?;
    let alias_bit = resolve_d128_stage1_alias::<P, A, C>(config, attrs.controls.global, pas)?;
    Ok(ResolvedStage1LeafAttrs {
        memory: Vmsa128Stage1Memory::resolve(config, attrs.memory)?,
        permissions: Stage1PermissionResolver::new(config).resolve(attrs.permissions)?,
        pas,
        controls: ResolvedVmsa128Stage1LeafControls {
            bbm_nt: attrs.controls.bbm_nt,
            not_dirty: attrs.controls.dirty_state.into(),
            shareability: RawShareability::from_bits(attrs.controls.shareability as u8)?,
            access_flag: attrs.controls.access_flag,
            alias_bit,
            contiguous: attrs.controls.contiguous,
            guarded: attrs.controls.guarded,
            protected: attrs.controls.protected,
            software: software_ten(attrs.controls.software)?,
        },
    })
}

const fn raw_vmsa128_stage1_leaf(
    resolved: ResolvedVmsa128Stage1LeafAttrs,
) -> RawVmsa128Stage1LeafAttrs {
    RawVmsa128Stage1LeafAttrs {
        attr_index: resolved.memory,
        bbm_nt: resolved.controls.bbm_nt,
        not_dirty: resolved.controls.not_dirty,
        shareability: resolved.controls.shareability,
        access_flag: resolved.controls.access_flag,
        alias_bit: resolved.controls.alias_bit,
        contiguous: resolved.controls.contiguous,
        guarded: resolved.controls.guarded,
        protected: resolved.controls.protected,
        permissions: resolved.permissions,
        ns: resolved.pas.ns,
        software: resolved.controls.software,
    }
}

pub(super) fn resolve_vmsa128_stage1_leaf<P, A, C>(
    config: &C,
    level: Level,
    attrs: SemanticStage1LeafAttrs<
        Stage1EffectivePermissions,
        A::LeafAttr,
        SemanticVmsa128Stage1LeafControls,
    >,
) -> Result<RawVmsa128Stage1LeafAttrs, AttrError>
where
    P: PrivilegeModel,
    A: Stage1PasResolver,
    C: Stage1MemoryConfig + Stage1PermissionConfig + D128AliasConfig,
{
    resolve_vmsa128_stage1_leaf_resolved::<P, A, C>(config, level, attrs)
        .map(raw_vmsa128_stage1_leaf)
}

pub(super) fn decode_vmsa128_stage1_leaf<P, A, C>(
    config: &C,
    raw: RawVmsa128Stage1LeafAttrs,
) -> Result<
    SemanticStage1LeafAttrs<
        Stage1EffectivePermissions,
        A::LeafAttr,
        SemanticVmsa128Stage1LeafControls,
    >,
    AttrError,
>
where
    P: PrivilegeModel,
    A: Stage1PasResolver,
    C: Stage1MemoryConfig + Stage1PermissionConfig + D128AliasConfig,
{
    let (nse, global) = decode_d128_stage1_alias::<P, A, C>(config, raw.alias_bit)?;
    Ok(SemanticStage1LeafAttrs {
        memory: Vmsa128Stage1Memory::decode(config, raw.attr_index)?,
        permissions: Stage1PermissionResolver::new(config).decode(raw.permissions)?,
        pas: A::decode_leaf(RawStage1LeafPas { ns: raw.ns, nse })?,
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

pub(super) fn resolve_vmsa128_stage1_table<A>(
    attrs: SemanticVmsa128Stage1TableAttrs<A::TableAttr>,
) -> Result<RawVmsa128Stage1TableAttrs, AttrError>
where
    A: Stage1PasResolver,
{
    let ns_table = A::resolve_table(attrs.pas)?;
    debug_assert_eq!(ns_table.is_some(), A::USES_NSTABLE);
    Ok(RawVmsa128Stage1TableAttrs {
        table_nt: attrs.table_nt,
        access_flag: attrs.access_flag,
        disch: attrs.disch,
        protected: attrs.protected,
        ns_table: ns_table.unwrap_or(false),
        software: software_ten(attrs.software)?,
    })
}

pub(super) fn decode_vmsa128_stage1_table<A>(
    raw: RawVmsa128Stage1TableAttrs,
) -> Result<SemanticVmsa128Stage1TableAttrs<A::TableAttr>, AttrError>
where
    A: Stage1PasResolver,
{
    Ok(SemanticVmsa128Stage1TableAttrs {
        table_nt: raw.table_nt,
        access_flag: raw.access_flag,
        disch: raw.disch,
        protected: raw.protected,
        pas: A::decode_table(raw.ns_table)?,
        software: SoftwareMetadata::new(raw.software.bits()),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolvedVmsa128Stage2LeafControls {
    pub bbm_nt: bool,
    pub dirty: Stage2Dirty,
    pub shareability: RawShareability,
    pub access_flag: bool,
    pub force_no_execute: bool,
    pub contiguous: bool,
    pub assured_only: bool,
    pub software: TenBit,
}

type ResolvedVmsa128Stage2LeafAttrs =
    ResolvedStage2LeafAttrs<FourBit, PermissionIndices, bool, ResolvedVmsa128Stage2LeafControls>;

fn resolve_vmsa128_stage2_leaf_fixed_resolved<C>(
    config: &C,
    level: Level,
    attrs: SemanticStage2LeafAttrs<Stage2Permission, (), SemanticVmsa128Stage2LeafControls>,
) -> Result<ResolvedVmsa128Stage2LeafAttrs, AttrError>
where
    C: Stage2MemoryConfig + Stage2PermissionConfig,
{
    resolve_vmsa128_stage2_leaf_inner(
        config,
        level,
        attrs.memory,
        attrs.permissions,
        resolve_fixed_nonsecure_stage2_pas(attrs.output_address_space),
        attrs.controls,
    )
}

fn resolve_vmsa128_stage2_leaf_realm_resolved<C>(
    config: &C,
    level: Level,
    attrs: SemanticStage2LeafAttrs<
        Stage2Permission,
        RealmOrNonSecurePa,
        SemanticVmsa128Stage2LeafControls,
    >,
) -> Result<ResolvedVmsa128Stage2LeafAttrs, AttrError>
where
    C: Stage2MemoryConfig + Stage2PermissionConfig,
{
    resolve_vmsa128_stage2_leaf_inner(
        config,
        level,
        attrs.memory,
        attrs.permissions,
        resolve_realm_stage2_pas(attrs.output_address_space),
        attrs.controls,
    )
}

fn resolve_vmsa128_stage2_leaf_secure_resolved<C>(
    config: &C,
    level: Level,
    attrs: SemanticStage2LeafAttrs<
        Stage2Permission,
        SecureSelectablePa,
        SemanticVmsa128Stage2LeafControls,
    >,
) -> Result<ResolvedVmsa128Stage2LeafAttrs, AttrError>
where
    C: Stage2MemoryConfig + Stage2PermissionConfig + PasConfig<Pas = SecureSelectablePa>,
{
    let ns = resolve_configured_secure_stage2_pas(config, attrs.output_address_space)?;
    resolve_vmsa128_stage2_leaf_inner(
        config,
        level,
        attrs.memory,
        attrs.permissions,
        ns,
        attrs.controls,
    )
}

fn resolve_vmsa128_stage2_leaf_inner<C>(
    config: &C,
    level: Level,
    memory: crate::attrs::Stage2MemoryAttributes,
    permissions: Stage2Permission,
    descriptor_ns: bool,
    controls: SemanticVmsa128Stage2LeafControls,
) -> Result<ResolvedVmsa128Stage2LeafAttrs, AttrError>
where
    C: Stage2MemoryConfig + Stage2PermissionConfig,
{
    require_nt(level, controls.bbm_nt)?;
    Ok(ResolvedStage2LeafAttrs {
        memory: resolve_stage2_memory(config, memory)?,
        permissions: Stage2PermissionResolver::new(config).resolve(permissions)?,
        output_address_space: descriptor_ns,
        controls: ResolvedVmsa128Stage2LeafControls {
            bbm_nt: controls.bbm_nt,
            dirty: controls.dirty_state.into(),
            shareability: RawShareability::from_bits(controls.shareability as u8)?,
            access_flag: controls.access_flag,
            force_no_execute: controls.force_no_execute,
            contiguous: controls.contiguous,
            assured_only: controls.assured_only,
            software: software_ten(controls.software)?,
        },
    })
}

const fn raw_vmsa128_stage2_leaf(
    resolved: ResolvedVmsa128Stage2LeafAttrs,
) -> RawVmsa128Stage2LeafAttrs {
    RawVmsa128Stage2LeafAttrs {
        mem_attr: resolved.memory,
        bbm_nt: resolved.controls.bbm_nt,
        dirty: resolved.controls.dirty,
        shareability: resolved.controls.shareability,
        access_flag: resolved.controls.access_flag,
        force_no_execute: resolved.controls.force_no_execute,
        contiguous: resolved.controls.contiguous,
        assured_only: resolved.controls.assured_only,
        permissions: resolved.permissions,
        ns: resolved.output_address_space,
        software: resolved.controls.software,
    }
}

pub(super) fn resolve_vmsa128_stage2_leaf_fixed<C>(
    config: &C,
    level: Level,
    attrs: SemanticStage2LeafAttrs<Stage2Permission, (), SemanticVmsa128Stage2LeafControls>,
) -> Result<RawVmsa128Stage2LeafAttrs, AttrError>
where
    C: Stage2MemoryConfig + Stage2PermissionConfig,
{
    resolve_vmsa128_stage2_leaf_fixed_resolved(config, level, attrs).map(raw_vmsa128_stage2_leaf)
}

pub(super) fn resolve_vmsa128_stage2_leaf_realm<C>(
    config: &C,
    level: Level,
    attrs: SemanticStage2LeafAttrs<
        Stage2Permission,
        RealmOrNonSecurePa,
        SemanticVmsa128Stage2LeafControls,
    >,
) -> Result<RawVmsa128Stage2LeafAttrs, AttrError>
where
    C: Stage2MemoryConfig + Stage2PermissionConfig,
{
    resolve_vmsa128_stage2_leaf_realm_resolved(config, level, attrs).map(raw_vmsa128_stage2_leaf)
}

pub(super) fn resolve_vmsa128_stage2_leaf_secure<C>(
    config: &C,
    level: Level,
    attrs: SemanticStage2LeafAttrs<
        Stage2Permission,
        SecureSelectablePa,
        SemanticVmsa128Stage2LeafControls,
    >,
) -> Result<RawVmsa128Stage2LeafAttrs, AttrError>
where
    C: Stage2MemoryConfig + Stage2PermissionConfig + PasConfig<Pas = SecureSelectablePa>,
{
    resolve_vmsa128_stage2_leaf_secure_resolved(config, level, attrs).map(raw_vmsa128_stage2_leaf)
}

pub(super) fn decode_vmsa128_stage2_leaf_realm<C>(
    config: &C,
    raw: RawVmsa128Stage2LeafAttrs,
) -> Result<
    SemanticStage2LeafAttrs<
        Stage2Permission,
        RealmOrNonSecurePa,
        SemanticVmsa128Stage2LeafControls,
    >,
    AttrError,
>
where
    C: Stage2MemoryConfig + Stage2PermissionConfig,
{
    Ok(SemanticStage2LeafAttrs {
        memory: decode_stage2_memory(config, raw.mem_attr)?,
        permissions: Stage2PermissionResolver::new(config).decode(raw.permissions)?,
        output_address_space: decode_realm_stage2_pas(raw.ns),
        controls: SemanticVmsa128Stage2LeafControls {
            bbm_nt: raw.bbm_nt,
            dirty_state: raw.dirty.into(),
            shareability: decode_shareability(raw.shareability)?,
            access_flag: raw.access_flag,
            force_no_execute: raw.force_no_execute,
            contiguous: raw.contiguous,
            assured_only: raw.assured_only,
            software: SoftwareMetadata::new(raw.software.bits()),
        },
    })
}

pub(super) fn decode_vmsa128_stage2_leaf_fixed<C>(
    config: &C,
    raw: RawVmsa128Stage2LeafAttrs,
) -> Result<
    SemanticStage2LeafAttrs<Stage2Permission, (), SemanticVmsa128Stage2LeafControls>,
    AttrError,
>
where
    C: Stage2MemoryConfig + Stage2PermissionConfig,
{
    if raw.ns {
        return Err(AttrError::InvalidOutputAddressSpace);
    }
    Ok(SemanticStage2LeafAttrs {
        memory: decode_stage2_memory(config, raw.mem_attr)?,
        permissions: Stage2PermissionResolver::new(config).decode(raw.permissions)?,
        output_address_space: (),
        controls: decode_vmsa128_stage2_controls(raw)?,
    })
}

pub(super) fn decode_vmsa128_stage2_leaf_secure<C>(
    config: &C,
    raw: RawVmsa128Stage2LeafAttrs,
) -> Result<
    SemanticStage2LeafAttrs<
        Stage2Permission,
        SecureSelectablePa,
        SemanticVmsa128Stage2LeafControls,
    >,
    AttrError,
>
where
    C: Stage2MemoryConfig + Stage2PermissionConfig + PasConfig<Pas = SecureSelectablePa>,
{
    Ok(SemanticStage2LeafAttrs {
        memory: decode_stage2_memory(config, raw.mem_attr)?,
        permissions: Stage2PermissionResolver::new(config).decode(raw.permissions)?,
        output_address_space: super::decode_configured_secure_stage2_pas(config, raw.ns)?,
        controls: decode_vmsa128_stage2_controls(raw)?,
    })
}

fn decode_vmsa128_stage2_controls(
    raw: RawVmsa128Stage2LeafAttrs,
) -> Result<SemanticVmsa128Stage2LeafControls, AttrError> {
    Ok(SemanticVmsa128Stage2LeafControls {
        bbm_nt: raw.bbm_nt,
        dirty_state: raw.dirty.into(),
        shareability: decode_shareability(raw.shareability)?,
        access_flag: raw.access_flag,
        force_no_execute: raw.force_no_execute,
        contiguous: raw.contiguous,
        assured_only: raw.assured_only,
        software: SoftwareMetadata::new(raw.software.bits()),
    })
}

pub(super) fn resolve_vmsa128_stage2_table(
    attrs: SemanticVmsa128Stage2TableAttrs,
) -> Result<RawVmsa128Stage2TableAttrs, AttrError> {
    Ok(RawVmsa128Stage2TableAttrs {
        table_nt: attrs.table_nt,
        access_flag: attrs.access_flag,
        software: software_ten(attrs.software)?,
    })
}

pub(super) fn decode_vmsa128_stage2_table(
    raw: RawVmsa128Stage2TableAttrs,
) -> Result<SemanticVmsa128Stage2TableAttrs, AttrError> {
    Ok(SemanticVmsa128Stage2TableAttrs {
        table_nt: raw.table_nt,
        access_flag: raw.access_flag,
        software: SoftwareMetadata::new(raw.software.bits()),
    })
}

fn resolve_d128_stage1_alias<P, A, C>(
    config: &C,
    global: bool,
    pas: RawStage1LeafPas,
) -> Result<bool, AttrError>
where
    P: PrivilegeModel,
    A: Stage1PasResolver,
    C: D128AliasConfig,
{
    if A::USES_NSE {
        if config.d128_stage1_alias_kind() != D128Stage1AliasKind::NonSecureExtension || !global {
            return Err(AttrError::InvalidD128Alias);
        }
        Ok(pas.nse)
    } else if P::SUPPORTS_EL0 {
        if config.d128_stage1_alias_kind() != D128Stage1AliasKind::NonGlobal || pas.nse {
            return Err(AttrError::InvalidD128Alias);
        }
        Ok(!global)
    } else if global && !pas.nse {
        Ok(false)
    } else {
        Err(AttrError::InvalidD128Alias)
    }
}

fn decode_d128_stage1_alias<P, A, C>(config: &C, bit: bool) -> Result<(bool, bool), AttrError>
where
    P: PrivilegeModel,
    A: Stage1PasResolver,
    C: D128AliasConfig,
{
    if A::USES_NSE {
        if config.d128_stage1_alias_kind() != D128Stage1AliasKind::NonSecureExtension {
            return Err(AttrError::InvalidD128Alias);
        }
        Ok((bit, true))
    } else if P::SUPPORTS_EL0 {
        if config.d128_stage1_alias_kind() != D128Stage1AliasKind::NonGlobal {
            return Err(AttrError::InvalidD128Alias);
        }
        Ok((false, !bit))
    } else if bit {
        Err(AttrError::InvalidD128Alias)
    } else {
        Ok((false, true))
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
