use crate::attrs::{
    AttrError, FourBit, PasConfig, RawShareability, RawVmsa64Stage1LeafAttrs,
    RawVmsa64Stage1TableAttrs, RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs,
    RealmOrNonSecurePa, ResolvedStage1LeafAttrs, ResolvedStage1TableAttrs, ResolvedStage2LeafAttrs,
    SecureSelectablePa, SemanticStage1LeafAttrs, SemanticStage1TableAttrs, SemanticStage2LeafAttrs,
    SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
    SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, SoftwareMetadata,
    Stage2LeafPermissions, Stage2PermissionModel, ThreeBit,
};

use super::{
    RawStage1DirectLeafPermissions, RawStage1LeafPas, RawStage1TablePermissionLimits,
    Stage1DirectPermissionModel, Stage1MemoryConfig, Stage1PasResolver, Stage2MemoryConfig,
    decode_configured_secure_stage2_pas, decode_realm_stage2_pas, decode_shareability,
    decode_stage1_memory_3, decode_stage2_direct_permissions, decode_stage2_memory,
    encode_stage2_direct_permissions, resolve_configured_secure_stage2_pas,
    resolve_fixed_nonsecure_stage2_pas, resolve_realm_stage2_pas, resolve_stage1_memory_3,
    resolve_stage2_memory,
};

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
    let memory = resolve_stage1_memory_3(config, attrs.memory)?;
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

pub(super) fn resolve_vmsa64_stage1_leaf<P, A, C>(
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

pub(super) fn decode_vmsa64_stage1_leaf<P, A, C>(
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
        memory: decode_stage1_memory_3(config, raw.attr_index)?,
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

pub(super) fn resolve_vmsa64_stage1_table<P, A>(
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

pub(super) fn decode_vmsa64_stage1_table<P, A>(
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
