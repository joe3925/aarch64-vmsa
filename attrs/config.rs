use super::{
    AllocationHints, AttrError, CachePolicy, Cacheability, D128LeafAliasKind, DataAccess,
    DeviceMemoryType, FeatureDependentLeafAlias, MemoryAttributes, MemoryTransience,
    OutputAddressSpace, Shareability,
};

pub trait LiveAttributeConfiguration {
    fn mair(&self) -> u64;
    fn mair2(&self) -> Option<u64>;
    fn permission_indirection(&self) -> Option<PermissionIndirectionRegisters>;
    fn permission_overlay(&self) -> Option<PermissionOverlayRegisters>;
    fn output_address_space(&self) -> OutputAddressSpace;
    fn d128_leaf_alias_kind(&self) -> D128LeafAliasKind;
    fn effective_shareability(&self) -> Shareability;
}

impl<T> LiveAttributeConfiguration for &T
where
    T: LiveAttributeConfiguration + ?Sized,
{
    fn mair(&self) -> u64 {
        (**self).mair()
    }

    fn mair2(&self) -> Option<u64> {
        (**self).mair2()
    }

    fn permission_indirection(&self) -> Option<PermissionIndirectionRegisters> {
        (**self).permission_indirection()
    }

    fn permission_overlay(&self) -> Option<PermissionOverlayRegisters> {
        (**self).permission_overlay()
    }

    fn output_address_space(&self) -> OutputAddressSpace {
        (**self).output_address_space()
    }

    fn d128_leaf_alias_kind(&self) -> D128LeafAliasKind {
        (**self).d128_leaf_alias_kind()
    }

    fn effective_shareability(&self) -> Shareability {
        (**self).effective_shareability()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionIndirectionRegisters {
    pub privileged: u64,
    pub unprivileged: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionOverlayRegisters {
    pub privileged: u64,
    pub unprivileged: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectivePermissions {
    pub privileged_data: DataAccess,
    pub unprivileged_data: DataAccess,
    pub privileged_execute: bool,
    pub unprivileged_execute: bool,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct MairIndex<const BITS: u8>(u8);

impl<const BITS: u8> MairIndex<BITS> {
    pub(crate) const fn from_bits(bits: u128) -> Self {
        debug_assert!(BITS == 3 || BITS == 4);
        let mask = if BITS < 8 { (1u8 << BITS) - 1 } else { u8::MAX };
        Self(bits as u8 & mask)
    }

    pub(crate) const fn bits(self) -> u128 {
        self.0 as u128
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Stage2MemoryEncoding(u8);

impl Stage2MemoryEncoding {
    pub(crate) const fn from_bits(bits: u128) -> Self {
        Self((bits & 0xf) as u8)
    }

    pub(crate) const fn bits(self) -> u128 {
        self.0 as u128
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct PermissionIndirectionIndex(u8);

impl PermissionIndirectionIndex {
    pub(crate) const fn from_bits(bits: u128) -> Self {
        Self((bits & 0xf) as u8)
    }

    pub(crate) const fn bits(self) -> u128 {
        self.0 as u128
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct PermissionOverlayIndex(u8);

impl PermissionOverlayIndex {
    pub(crate) const fn from_bits(bits: u128) -> Self {
        Self((bits & 0xf) as u8)
    }

    pub(crate) const fn bits(self) -> u128 {
        self.0 as u128
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedD128Permissions {
    pub indirection: PermissionIndirectionIndex,
    pub overlay: PermissionOverlayIndex,
}

pub struct AttributeResolver<C>
where
    C: LiveAttributeConfiguration,
{
    config: C,
}

impl<C> AttributeResolver<C>
where
    C: LiveAttributeConfiguration,
{
    pub const fn new(config: C) -> Self {
        Self { config }
    }

    pub const fn configuration(&self) -> &C {
        &self.config
    }

    pub(crate) fn effective_shareability(&self) -> Shareability {
        self.config.effective_shareability()
    }

    pub(crate) fn resolve_stage1_memory<const INDEX_BITS: u8>(
        &self,
        attrs: MemoryAttributes,
    ) -> Result<MairIndex<INDEX_BITS>, AttrError> {
        debug_assert!(INDEX_BITS == 3 || INDEX_BITS == 4);
        let entry_count = match INDEX_BITS {
            3 => 8,
            4 => {
                if self.config.mair2().is_none() {
                    return Err(AttrError::Mair2Unavailable);
                }
                16
            }
            _ => return Err(AttrError::InvalidMairIndexWidth),
        };
        let requested = encode_mair_attribute(attrs)?;

        for index in 0..entry_count {
            if mair_entry_at(&self.config, index)? == requested {
                return Ok(MairIndex::from_bits(index as u128));
            }
        }

        Err(AttrError::MemoryAttributeNotConfigured)
    }

    pub(crate) fn resolve_stage2_memory(
        &self,
        attrs: MemoryAttributes,
    ) -> Result<Stage2MemoryEncoding, AttrError> {
        let bits = match attrs {
            MemoryAttributes::Device(device) => match device {
                DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck => 0b0000,
                DeviceMemoryType::NonGatheringNonReorderingEarlyAck => 0b0001,
                DeviceMemoryType::NonGatheringReorderingEarlyAck => 0b0010,
                DeviceMemoryType::GatheringReorderingEarlyAck => 0b0011,
            },
            MemoryAttributes::Normal { inner, outer } => {
                (encode_stage2_cacheability(outer)? << 2) | encode_stage2_cacheability(inner)?
            }
        };

        Ok(Stage2MemoryEncoding::from_bits(bits as u128))
    }

    pub(crate) fn resolve_d128_permissions(
        &self,
        permissions: EffectivePermissions,
    ) -> Result<ResolvedD128Permissions, AttrError> {
        let indirection = self
            .config
            .permission_indirection()
            .ok_or(AttrError::PermissionIndirectionUnavailable)?;
        let overlay = self
            .config
            .permission_overlay()
            .ok_or(AttrError::PermissionOverlayUnavailable)?;
        validate_permission_register_pair(indirection, overlay)?;

        for indirection_index in 0..16 {
            for overlay_index in 0..16 {
                if decode_effective_permissions(
                    indirection,
                    overlay,
                    indirection_index,
                    overlay_index,
                ) == Some(permissions)
                {
                    return Ok(ResolvedD128Permissions {
                        indirection: PermissionIndirectionIndex::from_bits(
                            indirection_index.into(),
                        ),
                        overlay: PermissionOverlayIndex::from_bits(overlay_index.into()),
                    });
                }
            }
        }

        Err(AttrError::PermissionCombinationNotConfigured)
    }

    pub(crate) fn decode_stage1_memory<const INDEX_BITS: u8>(
        &self,
        index: MairIndex<INDEX_BITS>,
    ) -> MemoryAttributes {
        debug_assert!(INDEX_BITS == 3 || INDEX_BITS == 4);
        debug_assert!(index.bits() < (1u128 << INDEX_BITS));
        let entry = mair_entry_at(&self.config, index.0).ok();
        debug_assert!(entry.is_some());
        let decoded = entry.and_then(decode_mair_attribute);
        debug_assert!(decoded.is_some());
        decoded.unwrap_or(MemoryAttributes::Device(
            DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
        ))
    }

    pub(crate) fn decode_stage2_memory(&self, encoding: Stage2MemoryEncoding) -> MemoryAttributes {
        debug_assert!(encoding.bits() <= 0xf);
        let decoded = decode_stage2_memory_encoding(encoding.0);
        debug_assert!(decoded.is_some());
        decoded.unwrap_or(MemoryAttributes::Device(
            DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
        ))
    }

    pub(crate) fn decode_d128_permissions(
        &self,
        permissions: ResolvedD128Permissions,
    ) -> EffectivePermissions {
        debug_assert!(permissions.indirection.bits() <= 0xf);
        debug_assert!(permissions.overlay.bits() <= 0xf);
        let indirection = self.config.permission_indirection();
        let overlay = self.config.permission_overlay();
        debug_assert!(indirection.is_some());
        debug_assert!(overlay.is_some());
        debug_assert!(matches!(
            (indirection, overlay),
            (Some(i), Some(o)) if validate_permission_register_pair(i, o).is_ok()
        ));

        match (indirection, overlay) {
            (Some(indirection), Some(overlay)) => {
                let decoded = decode_effective_permissions(
                    indirection,
                    overlay,
                    permissions.indirection.0,
                    permissions.overlay.0,
                );
                debug_assert!(decoded.is_some());
                decoded.unwrap_or(no_effective_permissions())
            }
            _ => no_effective_permissions(),
        }
    }

    pub(crate) fn encode_d128_stage2_alias(
        &self,
        alias: FeatureDependentLeafAlias,
    ) -> Result<bool, AttrError> {
        match (self.config.d128_leaf_alias_kind(), alias) {
            (D128LeafAliasKind::NonGlobal, FeatureDependentLeafAlias::NonGlobal(value))
            | (
                D128LeafAliasKind::ForceNoExecute,
                FeatureDependentLeafAlias::ForceNoExecute(value),
            )
            | (
                D128LeafAliasKind::NonSecureExtension,
                FeatureDependentLeafAlias::NonSecureExtension(value),
            ) => Ok(value),
            _ => Err(AttrError::InvalidD128Alias),
        }
    }

    pub(crate) fn decode_d128_stage2_alias(&self, encoded: bool) -> FeatureDependentLeafAlias {
        match self.config.d128_leaf_alias_kind() {
            D128LeafAliasKind::NonGlobal => FeatureDependentLeafAlias::NonGlobal(encoded),
            D128LeafAliasKind::ForceNoExecute => FeatureDependentLeafAlias::ForceNoExecute(encoded),
            D128LeafAliasKind::NonSecureExtension => {
                FeatureDependentLeafAlias::NonSecureExtension(encoded)
            }
        }
    }
}

fn mair_entry(register: u64, index: u8) -> u8 {
    debug_assert!(index < 8);
    (register >> (u32::from(index) * 8)) as u8
}

fn mair_entry_at<C>(config: &C, index: u8) -> Result<u8, AttrError>
where
    C: LiveAttributeConfiguration,
{
    match index {
        0..=7 => Ok(mair_entry(config.mair(), index)),
        8..=15 => config
            .mair2()
            .map(|register| mair_entry(register, index - 8))
            .ok_or(AttrError::Mair2Unavailable),
        _ => Err(AttrError::InvalidMairIndexWidth),
    }
}

fn encode_mair_attribute(attrs: MemoryAttributes) -> Result<u8, AttrError> {
    match attrs {
        MemoryAttributes::Device(device) => Ok(match device {
            DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck => 0x00,
            DeviceMemoryType::NonGatheringNonReorderingEarlyAck => 0x04,
            DeviceMemoryType::NonGatheringReorderingEarlyAck => 0x08,
            DeviceMemoryType::GatheringReorderingEarlyAck => 0x0c,
        }),
        MemoryAttributes::Normal { inner, outer } => {
            Ok((encode_mair_cacheability(outer)? << 4) | encode_mair_cacheability(inner)?)
        }
    }
}

fn encode_mair_cacheability(cacheability: Cacheability) -> Result<u8, AttrError> {
    match cacheability {
        Cacheability::NonCacheable => Ok(0b0100),
        Cacheability::Cacheable {
            policy,
            transience,
            allocation,
        } => {
            let policy_bits = match (policy, transience) {
                (CachePolicy::WriteThrough, MemoryTransience::Transient) => 0b0000,
                (CachePolicy::WriteBack, MemoryTransience::Transient) => 0b0100,
                (CachePolicy::WriteThrough, MemoryTransience::NonTransient) => 0b1000,
                (CachePolicy::WriteBack, MemoryTransience::NonTransient) => 0b1100,
            };
            let allocation_bits = encode_allocation_hints(allocation);
            if transience == MemoryTransience::Transient && allocation_bits == 0 {
                return Err(AttrError::UnencodableMemoryAttribute);
            }
            Ok(policy_bits | allocation_bits)
        }
    }
}

fn decode_mair_attribute(entry: u8) -> Option<MemoryAttributes> {
    if entry >> 4 == 0 {
        return match entry {
            0x00 => Some(MemoryAttributes::Device(
                DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
            )),
            0x04 => Some(MemoryAttributes::Device(
                DeviceMemoryType::NonGatheringNonReorderingEarlyAck,
            )),
            0x08 => Some(MemoryAttributes::Device(
                DeviceMemoryType::NonGatheringReorderingEarlyAck,
            )),
            0x0c => Some(MemoryAttributes::Device(
                DeviceMemoryType::GatheringReorderingEarlyAck,
            )),
            _ => None,
        };
    }

    Some(MemoryAttributes::Normal {
        inner: decode_mair_cacheability(entry & 0xf)?,
        outer: decode_mair_cacheability(entry >> 4)?,
    })
}

fn decode_mair_cacheability(bits: u8) -> Option<Cacheability> {
    match bits & 0xf {
        0b0100 => Some(Cacheability::NonCacheable),
        bits if bits & 0b11 != 0 => {
            let (policy, transience) = match bits >> 2 {
                0b00 => (CachePolicy::WriteThrough, MemoryTransience::Transient),
                0b01 => (CachePolicy::WriteBack, MemoryTransience::Transient),
                0b10 => (CachePolicy::WriteThrough, MemoryTransience::NonTransient),
                _ => (CachePolicy::WriteBack, MemoryTransience::NonTransient),
            };
            Some(Cacheability::Cacheable {
                policy,
                transience,
                allocation: decode_allocation_hints(bits),
            })
        }
        _ => None,
    }
}

const fn encode_allocation_hints(hints: AllocationHints) -> u8 {
    match hints {
        AllocationHints::None => 0b00,
        AllocationHints::WriteAllocate => 0b01,
        AllocationHints::ReadAllocate => 0b10,
        AllocationHints::ReadWriteAllocate => 0b11,
    }
}

const fn decode_allocation_hints(bits: u8) -> AllocationHints {
    match bits & 0b11 {
        0b00 => AllocationHints::None,
        0b01 => AllocationHints::WriteAllocate,
        0b10 => AllocationHints::ReadAllocate,
        _ => AllocationHints::ReadWriteAllocate,
    }
}

fn encode_stage2_cacheability(cacheability: Cacheability) -> Result<u8, AttrError> {
    match cacheability {
        Cacheability::NonCacheable => Ok(0b01),
        Cacheability::Cacheable {
            policy,
            transience: MemoryTransience::NonTransient,
            allocation: AllocationHints::ReadWriteAllocate,
        } => Ok(match policy {
            CachePolicy::WriteThrough => 0b10,
            CachePolicy::WriteBack => 0b11,
        }),
        _ => Err(AttrError::UnencodableMemoryAttribute),
    }
}

fn decode_stage2_memory_encoding(bits: u8) -> Option<MemoryAttributes> {
    match bits & 0xf {
        0b0000 => Some(MemoryAttributes::Device(
            DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck,
        )),
        0b0001 => Some(MemoryAttributes::Device(
            DeviceMemoryType::NonGatheringNonReorderingEarlyAck,
        )),
        0b0010 => Some(MemoryAttributes::Device(
            DeviceMemoryType::NonGatheringReorderingEarlyAck,
        )),
        0b0011 => Some(MemoryAttributes::Device(
            DeviceMemoryType::GatheringReorderingEarlyAck,
        )),
        bits if bits >> 2 != 0 && bits & 0b11 != 0 => Some(MemoryAttributes::Normal {
            inner: decode_stage2_cacheability(bits & 0b11),
            outer: decode_stage2_cacheability(bits >> 2),
        }),
        _ => None,
    }
}

fn decode_stage2_cacheability(bits: u8) -> Cacheability {
    match bits & 0b11 {
        0b01 => Cacheability::NonCacheable,
        0b10 => Cacheability::Cacheable {
            policy: CachePolicy::WriteThrough,
            transience: MemoryTransience::NonTransient,
            allocation: AllocationHints::ReadWriteAllocate,
        },
        0b11 => Cacheability::Cacheable {
            policy: CachePolicy::WriteBack,
            transience: MemoryTransience::NonTransient,
            allocation: AllocationHints::ReadWriteAllocate,
        },
        _ => {
            debug_assert!(false, "invalid stage-2 normal-memory cacheability");
            Cacheability::NonCacheable
        }
    }
}

fn validate_permission_register_pair(
    indirection: PermissionIndirectionRegisters,
    overlay: PermissionOverlayRegisters,
) -> Result<(), AttrError> {
    if indirection.unprivileged.is_some() == overlay.unprivileged.is_some() {
        Ok(())
    } else {
        Err(AttrError::InvalidD128Configuration)
    }
}

fn permission_entry(register: u64, index: u8) -> u8 {
    debug_assert!(index < 16);
    ((register >> (u32::from(index) * 4)) & 0xf) as u8
}

#[derive(Clone, Copy)]
struct RawPermissions {
    read: bool,
    write: bool,
    execute: bool,
    apply_overlay: bool,
}

fn decode_base_permissions(entry: u8) -> RawPermissions {
    let (read, write, execute) = match entry & 0xf {
        0b0000 | 0b0100 | 0b1011 | 0b1101 | 0b1111 => (false, false, false),
        0b0001 | 0b1000 | 0b1001 => (true, false, false),
        0b0010 => (false, false, true),
        0b0011 | 0b1010 => (true, false, true),
        0b0101 | 0b1100 => (true, true, false),
        0b0110 | 0b0111 | 0b1110 => (true, true, true),
        _ => unreachable!(),
    };
    RawPermissions {
        read,
        write,
        execute,
        apply_overlay: entry & 0b1000 == 0,
    }
}

fn apply_overlay(base: RawPermissions, overlay_entry: u8) -> RawPermissions {
    if !base.apply_overlay {
        return base;
    }
    let overlay_entry = overlay_entry & 0xf;
    let overlay_entry = if overlay_entry & 0b1000 == 0 {
        overlay_entry
    } else {
        0
    };
    RawPermissions {
        read: base.read && overlay_entry & 0b0001 != 0,
        write: base.write && overlay_entry & 0b0100 != 0,
        execute: base.execute && overlay_entry & 0b0010 != 0,
        apply_overlay: false,
    }
}

fn decode_effective_permissions(
    indirection: PermissionIndirectionRegisters,
    overlay: PermissionOverlayRegisters,
    indirection_index: u8,
    overlay_index: u8,
) -> Option<EffectivePermissions> {
    debug_assert!(indirection_index < 16);
    debug_assert!(overlay_index < 16);
    let mut privileged =
        decode_base_permissions(permission_entry(indirection.privileged, indirection_index));
    let mut unprivileged = match indirection.unprivileged {
        Some(indirection) => {
            decode_base_permissions(permission_entry(indirection, indirection_index))
        }
        None => no_raw_permissions(),
    };
    if privileged.execute && unprivileged.write {
        privileged = no_raw_permissions();
        unprivileged = no_raw_permissions();
    }
    privileged = apply_overlay(
        privileged,
        permission_entry(overlay.privileged, overlay_index),
    );
    unprivileged = match overlay.unprivileged {
        Some(overlay) => apply_overlay(unprivileged, permission_entry(overlay, overlay_index)),
        None if indirection.unprivileged.is_none() => no_raw_permissions(),
        _ => {
            debug_assert!(false, "mismatched D128 unprivileged permission registers");
            no_raw_permissions()
        }
    };

    Some(EffectivePermissions {
        privileged_data: raw_data_access(privileged)?,
        unprivileged_data: raw_data_access(unprivileged)?,
        privileged_execute: privileged.execute,
        unprivileged_execute: unprivileged.execute,
    })
}

const fn no_raw_permissions() -> RawPermissions {
    RawPermissions {
        read: false,
        write: false,
        execute: false,
        apply_overlay: false,
    }
}

const fn raw_data_access(permissions: RawPermissions) -> Option<DataAccess> {
    match (permissions.read, permissions.write) {
        (false, false) => Some(DataAccess::None),
        (true, false) => Some(DataAccess::ReadOnly),
        (true, true) => Some(DataAccess::ReadWrite),
        (false, true) => None,
    }
}

const fn no_effective_permissions() -> EffectivePermissions {
    EffectivePermissions {
        privileged_data: DataAccess::None,
        unprivileged_data: DataAccess::None,
        privileged_execute: false,
        unprivileged_execute: false,
    }
}
