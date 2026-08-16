use crate::address::{Level, TranslationGranule};
use crate::attrs::{
    AttrError, DirtyBitManagement, DirtyControl, DirtyState, FourBit, LeafAp, MemoryAttributes,
    PermissionIndices, RawShareability, RawVmsa64PermissionFields, RawVmsa64Stage1LeafAttrs,
    RawVmsa64Stage1TableAttrs, RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs,
    SemanticLeafAttrs, SemanticStage1LeafAttrs, SemanticStage1TableAttrs, SemanticStage2LeafAttrs,
    SemanticTableAttrs, SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
    SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
    SoftwareMetadata, Stage1EffectivePermissions, Stage2Ap, Stage2ExecuteNever,
    Stage2MemoryAttributes, Stage2PasContext, Stage2Permission, Stage2PermissionModel, ThreeBit,
};
use crate::config::format::{Vmsa64, Vmsa64Lpa2};
use crate::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
use crate::regime::{RegimeLeafFields, RegimeTableFields, Stage1Regime, Stage2Regime};
use crate::translation::{Stage1, Stage2};

use super::codec::AttributeCodecCell;
use super::{
    HasMemoryCodec, MemoryAttributeCodec, RawStage1DirectLeafPermissions, RawStage1LeafPas,
    RawStage1TablePermissionLimits, ShareabilityConfig, Stage1BasePermissions,
    Stage1DirectPermissionModel, Stage1MemoryConfig, Stage1PasResolver, Stage1PermissionConfig,
    Stage1PermissionResolver, Stage2BasePermissions, Stage2MemoryConfig, Stage2PasResolver,
    Stage2PermissionConfig, Stage2PermissionResolver, apply_stage1_overlay, apply_stage2_overlay,
    decode_shareability, decode_stage2_direct_permissions, require_effective_shareability,
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

fn encode_stage1_leaf_core<F, P, A, C>(
    config: &C,
    attrs: SemanticStage1LeafAttrs<
        Stage1EffectivePermissions,
        A::LeafAttr,
        SemanticVmsa64Stage1LeafControls,
    >,
) -> Result<RawVmsa64Stage1LeafAttrs, AttrError>
where
    F: HasMemoryCodec<Stage1>,
    F::Codec: MemoryAttributeCodec<Stage1, C, Semantic = MemoryAttributes, Raw = FourBit>,
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
    C: Stage1MemoryConfig + Stage1PermissionConfig,
{
    let attr_index = F::Codec::encode(config, attrs.memory)?;
    let settings = config.stage1_permissions();
    let permissions = match settings.base {
        Stage1BasePermissions::Direct => {
            let dbm = match attrs.controls.dirty {
                DirtyControl::Direct(DirtyBitManagement::SoftwareManaged) => false,
                DirtyControl::Direct(DirtyBitManagement::HardwareManaged) => true,
                DirtyControl::Indirect(_) => return Err(AttrError::PermissionModeMismatch),
            };
            let mut encoding = None;
            'permissions: for ap in 0..4 {
                for pxn in [false, true] {
                    for uxn in [false, true] {
                        let direct = RawStage1DirectLeafPermissions {
                            ap: LeafAp::from_bits(ap)?,
                            privileged_execute_never: pxn,
                            unprivileged_execute_never: uxn,
                        };
                        let Ok(base) = P::decode_leaf(direct) else {
                            continue;
                        };
                        let po_count = if settings.overlays.privileged.is_some()
                            || settings.overlays.unprivileged.is_some()
                        {
                            8
                        } else {
                            1
                        };
                        for po in 0..po_count {
                            let effective = if settings.overlays.privileged.is_some()
                                || settings.overlays.unprivileged.is_some()
                            {
                                apply_stage1_overlay(base, settings.overlays, po)
                            } else {
                                Some(base)
                            };
                            if effective == Some(attrs.permissions) {
                                encoding = Some(RawVmsa64PermissionFields {
                                    primary: FourBit::new(
                                        (ap & 1)
                                            | (dbm as u8) << 1
                                            | (pxn as u8) << 2
                                            | (uxn as u8) << 3,
                                    )?,
                                    dirty: ap & 2 != 0,
                                    overlay: ThreeBit::new(po)?,
                                });
                                break 'permissions;
                            }
                        }
                    }
                }
            }
            encoding.ok_or(AttrError::UnencodablePermissions)?
        }
        Stage1BasePermissions::Indirect(_) => {
            let state = match attrs.controls.dirty {
                DirtyControl::Indirect(state) => state,
                DirtyControl::Direct(_) => return Err(AttrError::PermissionModeMismatch),
            };
            let indices =
                Stage1PermissionResolver::<C, ThreeBit>::new(config).resolve(attrs.permissions)?;
            RawVmsa64PermissionFields {
                primary: indices.pi,
                dirty: matches!(state, DirtyState::Clean),
                overlay: indices.po,
            }
        }
    };
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
        permissions,
        shareability: RawShareability::from_bits(attrs.controls.shareability as u8)?,
        access_flag: attrs.controls.access_flag,
        alias_bit,
        contiguous: attrs.controls.contiguous,
        guarded: attrs.controls.guarded,
        software: software_four(attrs.controls.software)?,
    })
}

fn decode_stage1_leaf_core<F, P, A, C>(
    config: &C,
    raw: RawVmsa64Stage1LeafAttrs,
) -> Result<
    SemanticStage1LeafAttrs<
        Stage1EffectivePermissions,
        A::LeafAttr,
        SemanticVmsa64Stage1LeafControls,
    >,
    AttrError,
>
where
    F: HasMemoryCodec<Stage1>,
    F::Codec: MemoryAttributeCodec<Stage1, C, Semantic = MemoryAttributes, Raw = FourBit>,
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
    C: Stage1MemoryConfig + Stage1PermissionConfig,
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
    let settings = config.stage1_permissions();
    let (permissions, dirty) = match settings.base {
        Stage1BasePermissions::Direct => {
            let bits = raw.permissions.primary.bits();
            let base = P::decode_leaf(RawStage1DirectLeafPermissions {
                ap: LeafAp::from_bits((bits & 1) | (raw.permissions.dirty as u8) << 1)?,
                privileged_execute_never: bits & 4 != 0,
                unprivileged_execute_never: bits & 8 != 0,
            })?;
            (
                if settings.overlays.privileged.is_some()
                    || settings.overlays.unprivileged.is_some()
                {
                    apply_stage1_overlay(base, settings.overlays, raw.permissions.overlay.bits())
                        .ok_or(AttrError::UnencodablePermissions)?
                } else {
                    base
                },
                DirtyControl::Direct(if bits & 2 != 0 {
                    DirtyBitManagement::HardwareManaged
                } else {
                    DirtyBitManagement::SoftwareManaged
                }),
            )
        }
        Stage1BasePermissions::Indirect(_) => (
            Stage1PermissionResolver::<C, ThreeBit>::new(config).decode(PermissionIndices {
                pi: raw.permissions.primary,
                po: raw.permissions.overlay,
            })?,
            DirtyControl::Indirect(if raw.permissions.dirty {
                DirtyState::Clean
            } else {
                DirtyState::Dirty
            }),
        ),
    };
    Ok(SemanticStage1LeafAttrs {
        memory: F::Codec::decode(config, raw.attr_index)?,
        permissions,
        pas: A::decode_leaf(RawStage1LeafPas { ns: raw.ns, nse })?,
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: decode_shareability(raw.shareability)?,
            access_flag: raw.access_flag,
            global,
            dirty,
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
        access_flag: attrs.controls.access_flag,
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
            access_flag: raw.access_flag,
            software: SoftwareMetadata::new(raw.software.bits().into()),
        },
    })
}

impl<R, G, Cfg> AttributeCodecCell<Vmsa64, R, G, Cfg> for Stage1
where
    R: Stage1Regime<Stage = Stage1>,
    G: TranslationGranule,
    Cfg: Stage1MemoryConfig + Stage1PermissionConfig,
    R::PrivilegeModel: Stage1DirectPermissionModel,
    R::PasModel: Stage1PasResolver,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64, R>,
    ) -> Result<RegimeLeafFields<Vmsa64, R, G>, AttrError> {
        encode_stage1_leaf_core::<Vmsa64, R::PrivilegeModel, R::PasModel, Cfg>(config, attrs)
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
        decode_stage1_leaf_core::<Vmsa64, R::PrivilegeModel, R::PasModel, Cfg>(config, raw)
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
    Cfg: Stage1MemoryConfig + Stage1PermissionConfig + ShareabilityConfig,
    R::PrivilegeModel: Stage1DirectPermissionModel,
    R::PasModel: Stage1PasResolver,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64Lpa2, R>,
    ) -> Result<RegimeLeafFields<Vmsa64Lpa2, R, G>, AttrError> {
        G::encode_shareability(config, attrs.controls.shareability)?;
        encode_stage1_leaf_core::<Vmsa64Lpa2, R::PrivilegeModel, R::PasModel, Cfg>(config, attrs)
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
        let mut attrs = decode_stage1_leaf_core::<Vmsa64Lpa2, R::PrivilegeModel, R::PasModel, Cfg>(
            config, raw,
        )?;
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

fn encode_stage2_leaf_core<F, P, A, C>(
    config: &C,
    attrs: SemanticStage2LeafAttrs<
        Stage2Permission,
        A::OutputAddressSpaceAttr,
        SemanticVmsa64Stage2LeafControls,
    >,
) -> Result<RawVmsa64Stage2LeafAttrs, AttrError>
where
    F: HasMemoryCodec<Stage2>,
    F::Codec: MemoryAttributeCodec<Stage2, C, Semantic = Stage2MemoryAttributes, Raw = FourBit>,
    P: Stage2PermissionModel,
    A: Stage2PasContext + Stage2PasResolver<Vmsa64, C, Software = FourBit>,
    C: Stage2MemoryConfig + Stage2PermissionConfig,
{
    let mut software = software_four(attrs.controls.software)?;
    let _descriptor_ns = A::resolve(config, attrs.output_address_space, &mut software)?;
    let mem_attr = F::Codec::encode(config, attrs.memory)?;
    let settings = config.stage2_permissions();
    let permissions = match settings.base {
        Stage2BasePermissions::Direct => {
            let dbm = match attrs.controls.dirty {
                DirtyControl::Direct(DirtyBitManagement::SoftwareManaged) => false,
                DirtyControl::Direct(DirtyBitManagement::HardwareManaged) => true,
                DirtyControl::Indirect(_) => return Err(AttrError::PermissionModeMismatch),
            };
            if !P::XNX
                && matches!(
                    attrs.permissions,
                    Stage2Permission::ReadOnly {
                        privileged_execute,
                        unprivileged_execute,
                    } | Stage2Permission::ReadWrite {
                        privileged_execute,
                        unprivileged_execute,
                    } if privileged_execute != unprivileged_execute
                )
            {
                return Err(AttrError::InvalidStage2ExecuteNever);
            }
            let mut encoding = None;
            'permissions: for ap in 0..4 {
                for xn in 0..4 {
                    let Ok(base) = decode_stage2_direct_permissions(
                        Stage2Ap::from_bits(ap)?,
                        Stage2ExecuteNever::from_bits(xn)?,
                        P::XNX,
                    ) else {
                        continue;
                    };
                    let po_count = if settings.s2por_el1.is_some() { 8 } else { 1 };
                    for po in 0..po_count {
                        if apply_stage2_overlay(base, settings.s2por_el1, po) == attrs.permissions {
                            encoding = Some(RawVmsa64PermissionFields {
                                primary: FourBit::new((ap & 1) | (dbm as u8) << 1 | xn << 2)?,
                                dirty: ap & 2 != 0,
                                overlay: ThreeBit::new(po)?,
                            });
                            break 'permissions;
                        }
                    }
                }
            }
            encoding.ok_or(AttrError::UnencodablePermissions)?
        }
        Stage2BasePermissions::Indirect(_) => {
            let state = match attrs.controls.dirty {
                DirtyControl::Indirect(state) => state,
                DirtyControl::Direct(_) => return Err(AttrError::PermissionModeMismatch),
            };
            let indices =
                Stage2PermissionResolver::<C, ThreeBit>::new(config).resolve(attrs.permissions)?;
            RawVmsa64PermissionFields {
                primary: indices.pi,
                dirty: matches!(state, DirtyState::Dirty),
                overlay: indices.po,
            }
        }
    };
    Ok(RawVmsa64Stage2LeafAttrs {
        mem_attr,
        permissions,
        shareability: RawShareability::from_bits(attrs.controls.shareability as u8)?,
        access_flag: attrs.controls.access_flag,
        contiguous: attrs.controls.contiguous,
        software,
    })
}

fn decode_stage2_leaf_core<F, P, A, C>(
    config: &C,
    raw: RawVmsa64Stage2LeafAttrs,
) -> Result<
    SemanticStage2LeafAttrs<
        Stage2Permission,
        A::OutputAddressSpaceAttr,
        SemanticVmsa64Stage2LeafControls,
    >,
    AttrError,
>
where
    F: HasMemoryCodec<Stage2>,
    F::Codec: MemoryAttributeCodec<Stage2, C, Semantic = Stage2MemoryAttributes, Raw = FourBit>,
    P: Stage2PermissionModel,
    A: Stage2PasContext + Stage2PasResolver<Vmsa64, C, Software = FourBit>,
    C: Stage2MemoryConfig + Stage2PermissionConfig,
{
    let mut software = raw.software;
    let output_address_space = A::decode(config, false, &mut software)?;
    let settings = config.stage2_permissions();
    let (permissions, dirty) = match settings.base {
        Stage2BasePermissions::Direct => {
            let bits = raw.permissions.primary.bits();
            let base = decode_stage2_direct_permissions(
                Stage2Ap::from_bits((bits & 1) | (raw.permissions.dirty as u8) << 1)?,
                Stage2ExecuteNever::from_bits((bits >> 2) & 3)?,
                P::XNX,
            )?;
            (
                apply_stage2_overlay(base, settings.s2por_el1, raw.permissions.overlay.bits()),
                DirtyControl::Direct(if bits & 2 != 0 {
                    DirtyBitManagement::HardwareManaged
                } else {
                    DirtyBitManagement::SoftwareManaged
                }),
            )
        }
        Stage2BasePermissions::Indirect(_) => (
            Stage2PermissionResolver::<C, ThreeBit>::new(config).decode(PermissionIndices {
                pi: raw.permissions.primary,
                po: raw.permissions.overlay,
            })?,
            DirtyControl::Indirect(if raw.permissions.dirty {
                DirtyState::Dirty
            } else {
                DirtyState::Clean
            }),
        ),
    };
    Ok(SemanticStage2LeafAttrs {
        memory: F::Codec::decode(config, raw.mem_attr)?,
        permissions,
        output_address_space,
        controls: SemanticVmsa64Stage2LeafControls {
            shareability: decode_shareability(raw.shareability)?,
            access_flag: raw.access_flag,
            dirty,
            contiguous: raw.contiguous,
            software: SoftwareMetadata::new(software.bits().into()),
        },
    })
}

fn encode_stage2_table_core(
    attrs: SemanticVmsa64Stage2TableAttrs,
) -> Result<RawVmsa64Stage2TableAttrs, AttrError> {
    Ok(RawVmsa64Stage2TableAttrs {
        access_flag: attrs.access_flag,
        software: software_four(attrs.software)?,
    })
}

fn decode_stage2_table_core(
    raw: RawVmsa64Stage2TableAttrs,
) -> Result<SemanticVmsa64Stage2TableAttrs, AttrError> {
    Ok(SemanticVmsa64Stage2TableAttrs {
        access_flag: raw.access_flag,
        software: SoftwareMetadata::new(raw.software.bits().into()),
    })
}

impl<R, G, Cfg> AttributeCodecCell<Vmsa64, R, G, Cfg> for Stage2
where
    R: Stage2Regime<Stage = Stage2>,
    G: TranslationGranule,
    Cfg: Stage2MemoryConfig + Stage2PermissionConfig,
    R::PasModel: Stage2PasContext + Stage2PasResolver<Vmsa64, Cfg, Software = FourBit>,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64, R>,
    ) -> Result<RegimeLeafFields<Vmsa64, R, G>, AttrError> {
        encode_stage2_leaf_core::<Vmsa64, R::PermissionModel, R::PasModel, Cfg>(config, attrs)
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
        decode_stage2_leaf_core::<Vmsa64, R::PermissionModel, R::PasModel, Cfg>(config, raw)
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
    Cfg: Stage2MemoryConfig + Stage2PermissionConfig + ShareabilityConfig,
    R::PasModel: Stage2PasContext + Stage2PasResolver<Vmsa64, Cfg, Software = FourBit>,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64Lpa2, R>,
    ) -> Result<RegimeLeafFields<Vmsa64Lpa2, R, G>, AttrError> {
        G::encode_shareability(config, attrs.controls.shareability)?;
        encode_stage2_leaf_core::<Vmsa64Lpa2, R::PermissionModel, R::PasModel, Cfg>(config, attrs)
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
        let mut attrs = decode_stage2_leaf_core::<Vmsa64Lpa2, R::PermissionModel, R::PasModel, Cfg>(
            config, raw,
        )?;
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
