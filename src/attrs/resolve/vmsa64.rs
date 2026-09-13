use crate::address::{Level, TranslationGranule};
use crate::attrs::SemanticAttributeTypes;
use crate::attrs::{
    AttrError, DirtyBitManagement, DirtyControl, DirtyState, FourBit, LeafAp, MemoryAttributes,
    PermissionIndices, PrivilegeModel, RawShareability, RawVmsa64PermissionFields,
    RawVmsa64Stage1LeafAttrs, RawVmsa64Stage1TableAttrs, RawVmsa64Stage2LeafAttrs,
    RawVmsa64Stage2TableAttrs, SemanticLeafAttrs, SemanticStage1LeafAttrs,
    SemanticStage1TableAttrs, SemanticStage2LeafAttrs, SemanticTableAttrs,
    SemanticVmsa64Stage1LeafControls, SemanticVmsa64Stage1TableControls,
    SemanticVmsa64Stage2LeafControls, SemanticVmsa64Stage2TableAttrs, Shareability,
    SoftwareMetadata, Stage1PasModel, Stage1Permissions, Stage2Ap, Stage2ExecuteNever,
    Stage2MemoryAttributes, Stage2PasContext, Stage2Permissions, ThreeBit,
};
use crate::config::format::{DescriptorEndian, Vmsa64, Vmsa64Lpa2};
use crate::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
use crate::descriptor::{DescriptorInterpretation, HasLayout, InterpretsDescriptors};
use crate::regime::{
    HasRegimeLayout, InterpretedLeafFields, InterpretedTableFields, Stage1PrivilegeModel,
    Stage1Regime, Stage2Regime,
};
use crate::translation::{Stage1, Stage2};

use super::codec::AttributeCodec;
use super::{
    HasMemoryCodec, MemoryAttributeCodec, PermissionCodec, RawStage1DirectLeafPermissions,
    RawStage1LeafPas, RawStage1TablePermissionLimits, ShareabilityConfig, Stage1BasePermissions,
    Stage1DirectPermissionModel, Stage1MemoryConfig, Stage1PasResolver, Stage1PermissionConfig,
    Stage1PermissionEncoding, Stage2BasePermissions, Stage2DirectEncoding, Stage2MemoryConfig,
    Stage2PasResolver, Stage2PermissionConfig, Stage2PermissionEncoding, decode_shareability,
    decode_smmuv3_stage1_memory, encode_smmuv3_stage1_memory, require_effective_shareability,
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

fn encode_stage1_leaf_core<F, P, A, C, I, K>(
    config: &C,
    attrs: SemanticStage1LeafAttrs<
        Stage1Permissions,
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
    I: DescriptorInterpretation,
    K: PermissionCodec<C, Stage1PermissionEncoding<ThreeBit>, Permissions = Stage1Permissions>,
{
    let attr_index = if I::USES_SMMUV3_STAGE1_MEMORY_ATTRIBUTES {
        encode_smmuv3_stage1_memory(config, attrs.memory)?
    } else {
        F::Codec::encode(config, attrs.memory)?
    };
    let settings = config.stage1_permissions();
    let permission_encoding = K::encode(config, attrs.permissions)?;
    let permissions = match (settings.base, permission_encoding) {
        (Stage1BasePermissions::Direct, Stage1PermissionEncoding::Direct(encoding)) => {
            let dbm = match attrs.controls.dirty {
                DirtyControl::Direct(DirtyBitManagement::SoftwareManaged) => false,
                DirtyControl::Direct(DirtyBitManagement::HardwareManaged) => true,
                DirtyControl::Indirect(_) => return Err(AttrError::PermissionModeMismatch),
            };
            let ap = encoding.leaf.ap.bits();
            RawVmsa64PermissionFields {
                primary: FourBit::new(
                    (ap & 1)
                        | (dbm as u8) << 1
                        | (encoding.leaf.privileged_execute_never as u8) << 2
                        | (encoding.leaf.unprivileged_execute_never as u8) << 3,
                )?,
                dirty: ap & 2 != 0,
                overlay: encoding.overlay,
            }
        }
        (Stage1BasePermissions::Indirect(_), Stage1PermissionEncoding::Indirect(indices)) => {
            let state = match attrs.controls.dirty {
                DirtyControl::Indirect(state) => state,
                DirtyControl::Direct(_) => return Err(AttrError::PermissionModeMismatch),
            };
            RawVmsa64PermissionFields {
                primary: indices.pi,
                dirty: matches!(state, DirtyState::Clean),
                overlay: indices.po,
            }
        }
        _ => return Err(AttrError::PermissionModeMismatch),
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

fn decode_stage1_leaf_core<F, P, A, C, I, K>(
    config: &C,
    raw: RawVmsa64Stage1LeafAttrs,
) -> Result<
    SemanticStage1LeafAttrs<Stage1Permissions, A::LeafAttr, SemanticVmsa64Stage1LeafControls>,
    AttrError,
>
where
    F: HasMemoryCodec<Stage1>,
    F::Codec: MemoryAttributeCodec<Stage1, C, Semantic = MemoryAttributes, Raw = FourBit>,
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
    C: Stage1MemoryConfig + Stage1PermissionConfig,
    I: DescriptorInterpretation,
    K: PermissionCodec<C, Stage1PermissionEncoding<ThreeBit>, Permissions = Stage1Permissions>,
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
    let (encoding, dirty) = match settings.base {
        Stage1BasePermissions::Direct => {
            let bits = raw.permissions.primary.bits();
            (
                Stage1PermissionEncoding::Direct(super::Stage1DirectEncoding {
                    leaf: RawStage1DirectLeafPermissions {
                        ap: LeafAp::from_bits((bits & 1) | (raw.permissions.dirty as u8) << 1)?,
                        privileged_execute_never: bits & 4 != 0,
                        unprivileged_execute_never: bits & 8 != 0,
                    },
                    overlay: raw.permissions.overlay,
                }),
                DirtyControl::Direct(if bits & 2 != 0 {
                    DirtyBitManagement::HardwareManaged
                } else {
                    DirtyBitManagement::SoftwareManaged
                }),
            )
        }
        Stage1BasePermissions::Indirect(_) => (
            Stage1PermissionEncoding::Indirect(PermissionIndices {
                pi: raw.permissions.primary,
                po: raw.permissions.overlay,
            }),
            DirtyControl::Indirect(if raw.permissions.dirty {
                DirtyState::Clean
            } else {
                DirtyState::Dirty
            }),
        ),
    };
    let permissions = K::decode(config, encoding)?;
    Ok(SemanticStage1LeafAttrs {
        memory: if I::USES_SMMUV3_STAGE1_MEMORY_ATTRIBUTES {
            decode_smmuv3_stage1_memory(config, raw.attr_index)?
        } else {
            F::Codec::decode(config, raw.attr_index)?
        },
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
        P::TableRestrictions,
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
    let restrictions = P::encode_table(attrs.restrictions)?;
    Ok(RawVmsa64Stage1TableAttrs {
        access_flag: attrs.controls.access_flag,
        privileged_execute_never_limit: restrictions.privileged_execute_never_limit,
        unprivileged_execute_never_limit: restrictions.unprivileged_execute_never_limit,
        ap_table: restrictions.ap_table,
        ns_table: ns_table.unwrap_or(false),
        software: software_four(attrs.controls.software)?,
    })
}

fn decode_stage1_table_core<P, A>(
    raw: RawVmsa64Stage1TableAttrs,
) -> Result<
    SemanticStage1TableAttrs<P::TableRestrictions, A::TableAttr, SemanticVmsa64Stage1TableControls>,
    AttrError,
>
where
    P: Stage1DirectPermissionModel,
    A: Stage1PasResolver,
{
    Ok(SemanticStage1TableAttrs {
        restrictions: P::decode_table(RawStage1TablePermissionLimits {
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

impl<E: DescriptorEndian, R, G, Cfg> AttributeCodec<Vmsa64<E>, R, G, Cfg> for Stage1
where
    R: Stage1Regime<Stage = Stage1>,
    G: TranslationGranule,
    Cfg: Stage1MemoryConfig + Stage1PermissionConfig,
    Stage1PrivilegeModel<R>: Stage1DirectPermissionModel,
    R::PermissionCodec:
        PermissionCodec<Cfg, Stage1PermissionEncoding<ThreeBit>, Permissions = Stage1Permissions>,
    R::PasModel: Stage1PasResolver,
    R::DescriptorInterpretation: InterpretsDescriptors<
            Vmsa64<E>,
            Stage1,
            G,
            Layout = <Vmsa64<E> as HasLayout<Stage1, G>>::Layout,
        >,
    Vmsa64<E>: HasRegimeLayout<R, G, Layout = <Vmsa64<E> as HasLayout<Stage1, G>>::Layout>
        + SemanticAttributeTypes<
            Stage1,
            R,
            Leaf = SemanticStage1LeafAttrs<
                Stage1Permissions,
                <R::PasModel as Stage1PasModel>::LeafAttr,
                SemanticVmsa64Stage1LeafControls,
            >,
            Table = SemanticStage1TableAttrs<
                <Stage1PrivilegeModel<R> as PrivilegeModel>::TableRestrictions,
                <R::PasModel as Stage1PasModel>::TableAttr,
                SemanticVmsa64Stage1TableControls,
            >,
        >,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64<E>, R>,
    ) -> Result<InterpretedLeafFields<Vmsa64<E>, R, G>, AttrError> {
        require_stage1_permission_semantics::<R::DescriptorInterpretation, _>(config)?;
        encode_stage1_leaf_core::<
            Vmsa64<E>,
            Stage1PrivilegeModel<R>,
            R::PasModel,
            Cfg,
            R::DescriptorInterpretation,
            R::PermissionCodec,
        >(config, attrs)
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa64<E>, R>,
    ) -> Result<InterpretedTableFields<Vmsa64<E>, R, G>, AttrError> {
        encode_stage1_table_core::<Stage1PrivilegeModel<R>, R::PasModel>(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: InterpretedLeafFields<Vmsa64<E>, R, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa64<E>, R>, AttrError> {
        require_stage1_permission_semantics::<R::DescriptorInterpretation, _>(config)?;
        decode_stage1_leaf_core::<
            Vmsa64<E>,
            Stage1PrivilegeModel<R>,
            R::PasModel,
            Cfg,
            R::DescriptorInterpretation,
            R::PermissionCodec,
        >(config, raw)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: InterpretedTableFields<Vmsa64<E>, R, G>,
    ) -> Result<SemanticTableAttrs<Vmsa64<E>, R>, AttrError> {
        decode_stage1_table_core::<Stage1PrivilegeModel<R>, R::PasModel>(raw)
    }
}

impl<E: DescriptorEndian, R, G, Cfg> AttributeCodec<Vmsa64Lpa2<E>, R, G, Cfg> for Stage1
where
    R: Stage1Regime<Stage = Stage1>,
    G: TranslationGranule + Lpa2GranulePolicy<Cfg>,
    Cfg: Stage1MemoryConfig + Stage1PermissionConfig + ShareabilityConfig,
    Stage1PrivilegeModel<R>: Stage1DirectPermissionModel,
    R::PermissionCodec:
        PermissionCodec<Cfg, Stage1PermissionEncoding<ThreeBit>, Permissions = Stage1Permissions>,
    R::PasModel: Stage1PasResolver,
    R::DescriptorInterpretation: InterpretsDescriptors<
            Vmsa64Lpa2<E>,
            Stage1,
            G,
            Layout = <Vmsa64Lpa2<E> as HasLayout<Stage1, G>>::Layout,
        >,
    Vmsa64Lpa2<E>: HasRegimeLayout<R, G, Layout = <Vmsa64Lpa2<E> as HasLayout<Stage1, G>>::Layout>
        + SemanticAttributeTypes<
            Stage1,
            R,
            Leaf = SemanticStage1LeafAttrs<
                Stage1Permissions,
                <R::PasModel as Stage1PasModel>::LeafAttr,
                SemanticVmsa64Stage1LeafControls,
            >,
            Table = SemanticStage1TableAttrs<
                <Stage1PrivilegeModel<R> as PrivilegeModel>::TableRestrictions,
                <R::PasModel as Stage1PasModel>::TableAttr,
                SemanticVmsa64Stage1TableControls,
            >,
        >,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64Lpa2<E>, R>,
    ) -> Result<InterpretedLeafFields<Vmsa64Lpa2<E>, R, G>, AttrError> {
        require_stage1_permission_semantics::<R::DescriptorInterpretation, _>(config)?;
        G::encode_shareability(config, attrs.controls.shareability)?;
        encode_stage1_leaf_core::<
            Vmsa64Lpa2<E>,
            Stage1PrivilegeModel<R>,
            R::PasModel,
            Cfg,
            R::DescriptorInterpretation,
            R::PermissionCodec,
        >(config, attrs)
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa64Lpa2<E>, R>,
    ) -> Result<InterpretedTableFields<Vmsa64Lpa2<E>, R, G>, AttrError> {
        encode_stage1_table_core::<Stage1PrivilegeModel<R>, R::PasModel>(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: InterpretedLeafFields<Vmsa64Lpa2<E>, R, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa64Lpa2<E>, R>, AttrError> {
        require_stage1_permission_semantics::<R::DescriptorInterpretation, _>(config)?;
        let mut attrs = decode_stage1_leaf_core::<
            Vmsa64Lpa2<E>,
            Stage1PrivilegeModel<R>,
            R::PasModel,
            Cfg,
            R::DescriptorInterpretation,
            R::PermissionCodec,
        >(config, raw)?;
        G::decode_shareability(config, &mut attrs.controls.shareability)?;
        Ok(attrs)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: InterpretedTableFields<Vmsa64Lpa2<E>, R, G>,
    ) -> Result<SemanticTableAttrs<Vmsa64Lpa2<E>, R>, AttrError> {
        decode_stage1_table_core::<Stage1PrivilegeModel<R>, R::PasModel>(raw)
    }
}

fn encode_stage2_leaf_core<F, A, C, K>(
    config: &C,
    attrs: SemanticStage2LeafAttrs<
        Stage2Permissions,
        A::OutputAddressSpaceAttr,
        SemanticVmsa64Stage2LeafControls,
    >,
) -> Result<RawVmsa64Stage2LeafAttrs, AttrError>
where
    F: HasMemoryCodec<Stage2>,
    F::Codec: MemoryAttributeCodec<Stage2, C, Semantic = Stage2MemoryAttributes, Raw = FourBit>,
    A: Stage2PasContext + Stage2PasResolver<F, C, Software = FourBit>,
    C: Stage2MemoryConfig + Stage2PermissionConfig,
    K: PermissionCodec<C, Stage2PermissionEncoding<ThreeBit>, Permissions = Stage2Permissions>,
{
    let mut software = software_four(attrs.controls.software)?;
    let _descriptor_ns = A::resolve(config, attrs.output_address_space, &mut software)?;
    let mem_attr = F::Codec::encode(config, attrs.memory)?;
    let settings = config.stage2_permissions();
    let permission_encoding = K::encode(config, attrs.permissions)?;
    let permissions = match (settings.base, permission_encoding) {
        (Stage2BasePermissions::Direct, Stage2PermissionEncoding::Direct(encoding)) => {
            let dbm = match attrs.controls.dirty {
                DirtyControl::Direct(DirtyBitManagement::SoftwareManaged) => false,
                DirtyControl::Direct(DirtyBitManagement::HardwareManaged) => true,
                DirtyControl::Indirect(_) => return Err(AttrError::PermissionModeMismatch),
            };
            let ap = encoding.access.bits();
            RawVmsa64PermissionFields {
                primary: FourBit::new(
                    (ap & 1) | (dbm as u8) << 1 | encoding.execute_never.bits() << 2,
                )?,
                dirty: ap & 2 != 0,
                overlay: ThreeBit::new(0)?,
            }
        }
        (Stage2BasePermissions::Indirect(_), Stage2PermissionEncoding::Indirect(indices)) => {
            let state = match attrs.controls.dirty {
                DirtyControl::Indirect(state) => state,
                DirtyControl::Direct(_) => return Err(AttrError::PermissionModeMismatch),
            };
            RawVmsa64PermissionFields {
                primary: indices.pi,
                dirty: matches!(state, DirtyState::Dirty),
                overlay: indices.po,
            }
        }
        _ => return Err(AttrError::PermissionModeMismatch),
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

fn decode_stage2_leaf_core<F, A, C, K>(
    config: &C,
    raw: RawVmsa64Stage2LeafAttrs,
) -> Result<
    SemanticStage2LeafAttrs<
        Stage2Permissions,
        A::OutputAddressSpaceAttr,
        SemanticVmsa64Stage2LeafControls,
    >,
    AttrError,
>
where
    F: HasMemoryCodec<Stage2>,
    F::Codec: MemoryAttributeCodec<Stage2, C, Semantic = Stage2MemoryAttributes, Raw = FourBit>,
    A: Stage2PasContext + Stage2PasResolver<F, C, Software = FourBit>,
    C: Stage2MemoryConfig + Stage2PermissionConfig,
    K: PermissionCodec<C, Stage2PermissionEncoding<ThreeBit>, Permissions = Stage2Permissions>,
{
    let mut software = raw.software;
    let output_address_space = A::decode(config, false, &mut software)?;
    let settings = config.stage2_permissions();
    let (encoding, dirty) = match settings.base {
        Stage2BasePermissions::Direct => {
            let bits = raw.permissions.primary.bits();
            let encoding = Stage2DirectEncoding {
                access: Stage2Ap::from_bits((bits & 1) | (raw.permissions.dirty as u8) << 1)?,
                execute_never: Stage2ExecuteNever::from_bits((bits >> 2) & 3)?,
            };
            (
                Stage2PermissionEncoding::Direct(encoding),
                DirtyControl::Direct(if bits & 2 != 0 {
                    DirtyBitManagement::HardwareManaged
                } else {
                    DirtyBitManagement::SoftwareManaged
                }),
            )
        }
        Stage2BasePermissions::Indirect(_) => (
            Stage2PermissionEncoding::Indirect(PermissionIndices {
                pi: raw.permissions.primary,
                po: raw.permissions.overlay,
            }),
            DirtyControl::Indirect(if raw.permissions.dirty {
                DirtyState::Dirty
            } else {
                DirtyState::Clean
            }),
        ),
    };
    let permissions = K::decode(config, encoding)?;
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

impl<E: DescriptorEndian, R, G, Cfg> AttributeCodec<Vmsa64<E>, R, G, Cfg> for Stage2
where
    R: Stage2Regime<Stage = Stage2>,
    G: TranslationGranule,
    Cfg: Stage2MemoryConfig + Stage2PermissionConfig,
    R::PermissionCodec:
        PermissionCodec<Cfg, Stage2PermissionEncoding<ThreeBit>, Permissions = Stage2Permissions>,
    R::PasModel: Stage2PasContext + Stage2PasResolver<Vmsa64<E>, Cfg, Software = FourBit>,
    R::DescriptorInterpretation: InterpretsDescriptors<
            Vmsa64<E>,
            Stage2,
            G,
            Layout = <Vmsa64<E> as HasLayout<Stage2, G>>::Layout,
        >,
    Vmsa64<E>: HasRegimeLayout<R, G, Layout = <Vmsa64<E> as HasLayout<Stage2, G>>::Layout>
        + SemanticAttributeTypes<
            Stage2,
            R,
            Leaf = SemanticStage2LeafAttrs<
                Stage2Permissions,
                <R::PasModel as Stage2PasContext>::OutputAddressSpaceAttr,
                SemanticVmsa64Stage2LeafControls,
            >,
            Table = SemanticVmsa64Stage2TableAttrs,
        >,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64<E>, R>,
    ) -> Result<InterpretedLeafFields<Vmsa64<E>, R, G>, AttrError> {
        encode_stage2_leaf_core::<Vmsa64<E>, R::PasModel, Cfg, R::PermissionCodec>(config, attrs)
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa64<E>, R>,
    ) -> Result<InterpretedTableFields<Vmsa64<E>, R, G>, AttrError> {
        encode_stage2_table_core(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: InterpretedLeafFields<Vmsa64<E>, R, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa64<E>, R>, AttrError> {
        decode_stage2_leaf_core::<Vmsa64<E>, R::PasModel, Cfg, R::PermissionCodec>(config, raw)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: InterpretedTableFields<Vmsa64<E>, R, G>,
    ) -> Result<SemanticTableAttrs<Vmsa64<E>, R>, AttrError> {
        decode_stage2_table_core(raw)
    }
}

impl<E: DescriptorEndian, R, G, Cfg> AttributeCodec<Vmsa64Lpa2<E>, R, G, Cfg> for Stage2
where
    R: Stage2Regime<Stage = Stage2>,
    G: TranslationGranule + Lpa2GranulePolicy<Cfg>,
    Cfg: Stage2MemoryConfig + Stage2PermissionConfig + ShareabilityConfig,
    R::PermissionCodec:
        PermissionCodec<Cfg, Stage2PermissionEncoding<ThreeBit>, Permissions = Stage2Permissions>,
    R::PasModel: Stage2PasContext + Stage2PasResolver<Vmsa64Lpa2<E>, Cfg, Software = FourBit>,
    R::DescriptorInterpretation: InterpretsDescriptors<
            Vmsa64Lpa2<E>,
            Stage2,
            G,
            Layout = <Vmsa64Lpa2<E> as HasLayout<Stage2, G>>::Layout,
        >,
    Vmsa64Lpa2<E>: HasRegimeLayout<R, G, Layout = <Vmsa64Lpa2<E> as HasLayout<Stage2, G>>::Layout>
        + SemanticAttributeTypes<
            Stage2,
            R,
            Leaf = SemanticStage2LeafAttrs<
                Stage2Permissions,
                <R::PasModel as Stage2PasContext>::OutputAddressSpaceAttr,
                SemanticVmsa64Stage2LeafControls,
            >,
            Table = SemanticVmsa64Stage2TableAttrs,
        >,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64Lpa2<E>, R>,
    ) -> Result<InterpretedLeafFields<Vmsa64Lpa2<E>, R, G>, AttrError> {
        G::encode_shareability(config, attrs.controls.shareability)?;
        encode_stage2_leaf_core::<Vmsa64Lpa2<E>, R::PasModel, Cfg, R::PermissionCodec>(
            config, attrs,
        )
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa64Lpa2<E>, R>,
    ) -> Result<InterpretedTableFields<Vmsa64Lpa2<E>, R, G>, AttrError> {
        encode_stage2_table_core(attrs)
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: InterpretedLeafFields<Vmsa64Lpa2<E>, R, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa64Lpa2<E>, R>, AttrError> {
        let mut attrs =
            decode_stage2_leaf_core::<Vmsa64Lpa2<E>, R::PasModel, Cfg, R::PermissionCodec>(
                config, raw,
            )?;
        G::decode_shareability(config, &mut attrs.controls.shareability)?;
        Ok(attrs)
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: InterpretedTableFields<Vmsa64Lpa2<E>, R, G>,
    ) -> Result<SemanticTableAttrs<Vmsa64Lpa2<E>, R>, AttrError> {
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
