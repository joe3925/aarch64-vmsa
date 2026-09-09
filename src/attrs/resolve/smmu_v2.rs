use crate::address::{Level, TranslationGranule};
use crate::attrs::{
    AttrError, DirtyBitManagement, DirtyControl, FourBit, NonSecureIpaContext, RawShareability,
    RawSmmuV2Stage2LeafAttrs, RawVmsa64Stage2TableAttrs, SemanticAttributeTypes, SemanticLeafAttrs,
    SemanticSmmuV2Stage2LeafControls, SemanticStage2LeafAttrs, SemanticTableAttrs,
    SemanticVmsa64Stage2TableAttrs, SmmuV2AllocationHint, SoftwareMetadata, Stage2Ap,
    Stage2ExecuteNever, Stage2Permission, TwoBit,
};
use crate::config::format::{DescriptorEndian, Vmsa64};
use crate::config::regime::smmu_v2::NonSecureIpaStage2;
use crate::descriptor::{InterpretsDescriptors, SmmuV2Descriptors, SmmuV2Vmsa64Stage2Layout};
use crate::regime::{InterpretedLeafFields, InterpretedTableFields};
use crate::translation::Stage2;

use super::codec::AttributeCodecCell;
use super::{
    HasMemoryCodec, MemoryAttributeCodec, Stage2MemoryConfig, Stage2PasResolver,
    decode_shareability, decode_stage2_direct_permissions,
};

impl<E: DescriptorEndian, G, Cfg> AttributeCodecCell<Vmsa64<E>, NonSecureIpaStage2, G, Cfg>
    for Stage2
where
    G: TranslationGranule,
    Cfg: Stage2MemoryConfig,
    SmmuV2Descriptors:
        InterpretsDescriptors<Vmsa64<E>, Stage2, G, Layout = SmmuV2Vmsa64Stage2Layout<E, G>>,
    Vmsa64<E>: SemanticAttributeTypes<
            Stage2,
            NonSecureIpaStage2,
            Leaf = SemanticStage2LeafAttrs<Stage2Permission, (), SemanticSmmuV2Stage2LeafControls>,
            Table = SemanticVmsa64Stage2TableAttrs,
        >,
{
    fn encode_leaf(
        config: &Cfg,
        _: Level,
        attrs: SemanticLeafAttrs<Vmsa64<E>, NonSecureIpaStage2>,
    ) -> Result<InterpretedLeafFields<Vmsa64<E>, NonSecureIpaStage2, G>, AttrError> {
        let permissions = encode_permissions(attrs.permissions)?;
        let dirty_bit_modifier = match attrs.controls.dirty {
            DirtyControl::Direct(DirtyBitManagement::SoftwareManaged) => false,
            DirtyControl::Direct(DirtyBitManagement::HardwareManaged) => true,
            DirtyControl::Indirect(_) => return Err(AttrError::PermissionModeMismatch),
        };
        let mut software = FourBit::new(attrs.controls.software.value() as u8)?;
        let _ = <NonSecureIpaContext as Stage2PasResolver<Vmsa64<E>, Cfg>>::resolve(
            config,
            attrs.output_address_space,
            &mut software,
        )?;
        Ok(RawSmmuV2Stage2LeafAttrs {
            mem_attr: <Vmsa64<E> as HasMemoryCodec<Stage2>>::Codec::encode(config, attrs.memory)?,
            permissions: permissions.0,
            shareability: RawShareability::from_bits(attrs.controls.shareability as u8)?,
            access_flag: attrs.controls.access_flag,
            dirty_bit_modifier,
            contiguous: attrs.controls.contiguous,
            execute_never: permissions.1,
            software,
            read_allocate: encode_allocation(attrs.controls.read_allocate)?,
            write_allocate: encode_allocation(attrs.controls.write_allocate)?,
        })
    }

    fn encode_table(
        _: &Cfg,
        _: Level,
        attrs: SemanticTableAttrs<Vmsa64<E>, NonSecureIpaStage2>,
    ) -> Result<InterpretedTableFields<Vmsa64<E>, NonSecureIpaStage2, G>, AttrError> {
        Ok(RawVmsa64Stage2TableAttrs {
            access_flag: attrs.access_flag,
            software: FourBit::new(attrs.software.value() as u8)?,
        })
    }

    fn decode_leaf(
        config: &Cfg,
        _: Level,
        raw: InterpretedLeafFields<Vmsa64<E>, NonSecureIpaStage2, G>,
    ) -> Result<SemanticLeafAttrs<Vmsa64<E>, NonSecureIpaStage2>, AttrError> {
        let mut software = raw.software;
        <NonSecureIpaContext as Stage2PasResolver<Vmsa64<E>, Cfg>>::decode(
            config,
            false,
            &mut software,
        )?;
        Ok(SemanticStage2LeafAttrs {
            memory: <Vmsa64<E> as HasMemoryCodec<Stage2>>::Codec::decode(config, raw.mem_attr)?,
            permissions: decode_stage2_direct_permissions(
                raw.permissions,
                Stage2ExecuteNever::from_bits(if raw.execute_never { 0b10 } else { 0b00 })?,
                false,
            )?,
            output_address_space: (),
            controls: SemanticSmmuV2Stage2LeafControls {
                shareability: decode_shareability(raw.shareability)?,
                access_flag: raw.access_flag,
                dirty: DirtyControl::Direct(if raw.dirty_bit_modifier {
                    DirtyBitManagement::HardwareManaged
                } else {
                    DirtyBitManagement::SoftwareManaged
                }),
                contiguous: raw.contiguous,
                read_allocate: decode_allocation(raw.read_allocate)?,
                write_allocate: decode_allocation(raw.write_allocate)?,
                software: SoftwareMetadata::new(software.bits().into()),
            },
        })
    }

    fn decode_table(
        _: &Cfg,
        _: Level,
        raw: InterpretedTableFields<Vmsa64<E>, NonSecureIpaStage2, G>,
    ) -> Result<SemanticTableAttrs<Vmsa64<E>, NonSecureIpaStage2>, AttrError> {
        Ok(SemanticVmsa64Stage2TableAttrs {
            access_flag: raw.access_flag,
            software: SoftwareMetadata::new(raw.software.bits().into()),
        })
    }
}

fn encode_permissions(wanted: Stage2Permission) -> Result<(Stage2Ap, bool), AttrError> {
    for ap in 0..=0b11 {
        for xn in [false, true] {
            let ap = Stage2Ap::from_bits(ap)?;
            let encoded_xn = Stage2ExecuteNever::from_bits(if xn { 0b10 } else { 0b00 })?;
            if decode_stage2_direct_permissions(ap, encoded_xn, false) == Ok(wanted) {
                return Ok((ap, xn));
            }
        }
    }
    Err(AttrError::UnencodablePermissions)
}

fn encode_allocation(value: SmmuV2AllocationHint) -> Result<TwoBit, AttrError> {
    TwoBit::new(match value {
        SmmuV2AllocationHint::UsePreviousStage => 0b00,
        SmmuV2AllocationHint::Allocate => 0b10,
        SmmuV2AllocationHint::NoAllocate => 0b11,
    })
}

fn decode_allocation(value: TwoBit) -> Result<SmmuV2AllocationHint, AttrError> {
    match value.bits() {
        0b00 | 0b01 => Ok(SmmuV2AllocationHint::UsePreviousStage),
        0b10 => Ok(SmmuV2AllocationHint::Allocate),
        0b11 => Ok(SmmuV2AllocationHint::NoAllocate),
        _ => Err(AttrError::InvalidSmmuV2AllocationHint),
    }
}
