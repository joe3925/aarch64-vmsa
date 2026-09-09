use crate::attrs::{
    AttrError, DataRights, El1And0Permissions, El2And0Permissions, El2Permissions, El3Permissions,
    FourBit, LeafAp, PermissionIndices, PrivilegeModel, SinglePrivilegeTableRestrictions,
    SmmuPrivilegedStreamPermissions, SmmuStreamPermissions, Stage1Permissions, TableAp,
    TwoPrivilegeTableRestrictions,
};
use crate::descriptor::{
    DescriptorInterpretation, PeDescriptors, SmmuV2Descriptors, SmmuV3Descriptors,
};

use super::Stage1PermissionConfig;
use super::{
    PeStage1PermissionCodec, PermissionCodec, PermissionIndex, SmmuV2Stage1PermissionCodec,
    SmmuV3Stage1PermissionCodec,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1PermissionRegisters {
    /// PE PIRE-style entries, or packed three-bit SMMUv3 CD.PIIP entries.
    pub privileged: u64,
    /// PE PIRE-style entries, or packed three-bit SMMUv3 CD.PIIU entries.
    pub unprivileged: Option<u64>,
    pub gcs_implemented: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage1BasePermissions {
    Direct,
    Indirect(Stage1PermissionRegisters),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stage1PermissionOverlays {
    pub privileged: Option<u64>,
    pub unprivileged: Option<u64>,
}

impl Stage1PermissionOverlays {
    fn apply(self, base: Stage1Permissions, index: u8) -> Option<Stage1Permissions> {
        let privileged = apply_effective_overlay(
            Stage1Access {
                read: base.data.privileged.permits_read(),
                write: base.data.privileged.permits_write(),
                execute: base.execute.privileged(),
                gcs: base.gcs.privileged,
                apply_overlay: true,
                wxn: false,
            },
            self.privileged,
            index,
        );
        let unprivileged = apply_effective_overlay(
            Stage1Access {
                read: base.data.unprivileged.permits_read(),
                write: base.data.unprivileged.permits_write(),
                execute: base.execute.unprivileged(),
                gcs: base.gcs.unprivileged,
                apply_overlay: true,
                wxn: false,
            },
            self.unprivileged,
            index,
        );
        if (privileged.execute || privileged.gcs) && (unprivileged.write || unprivileged.gcs) {
            return None;
        }
        Some(Stage1Permissions::new(
            data_access(privileged)?,
            data_access(unprivileged)?,
            privileged.execute,
            unprivileged.execute,
            privileged.gcs,
            unprivileged.gcs,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1PermissionSettings {
    pub base: Stage1BasePermissions,
    pub overlays: Stage1PermissionOverlays,
}

impl Stage1PermissionSettings {
    pub const fn direct() -> Self {
        Self {
            base: Stage1BasePermissions::Direct,
            overlays: Stage1PermissionOverlays {
                privileged: None,
                unprivileged: None,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage1BasePermission {
    NoAccessApplyOverlay,
    ReadApplyOverlay,
    ExecuteApplyOverlay,
    ReadExecuteApplyOverlay,
    ReservedNoAccessApplyOverlay,
    ReadWriteApplyOverlay,
    ReadWriteExecuteApplyOverlayWithWxn,
    ReadWriteExecuteApplyOverlay,
    ReadNoOverlay,
    ReadGcsNoOverlay,
    ReadExecuteNoOverlay,
    ReservedNoAccessNoOverlay,
    ReadWriteNoOverlay,
    ReadWriteExecuteNoOverlay,
}

impl Stage1BasePermission {
    const fn from_raw(raw: u8) -> Self {
        match raw & 0b1111 {
            0b0000 => Self::NoAccessApplyOverlay,
            0b0001 => Self::ReadApplyOverlay,
            0b0010 => Self::ExecuteApplyOverlay,
            0b0011 => Self::ReadExecuteApplyOverlay,
            0b0100 => Self::ReservedNoAccessApplyOverlay,
            0b0101 => Self::ReadWriteApplyOverlay,
            0b0110 => Self::ReadWriteExecuteApplyOverlayWithWxn,
            0b0111 => Self::ReadWriteExecuteApplyOverlay,
            0b1000 => Self::ReadNoOverlay,
            0b1001 => Self::ReadGcsNoOverlay,
            0b1010 => Self::ReadExecuteNoOverlay,
            0b1100 => Self::ReadWriteNoOverlay,
            0b1110 => Self::ReadWriteExecuteNoOverlay,
            _ => Self::ReservedNoAccessNoOverlay,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmmuV3Stage1BasePermission {
    NoAccess,
    ReadOnly,
    ExecuteOnly,
    ReadExecute,
    ReservedNoAccess,
    ReadWrite,
    ReadWriteExecute,
}

impl SmmuV3Stage1BasePermission {
    const fn from_raw(raw: u8) -> Self {
        match raw & 0b111 {
            0b000 => Self::NoAccess,
            0b001 => Self::ReadOnly,
            0b010 => Self::ExecuteOnly,
            0b011 => Self::ReadExecute,
            0b101 => Self::ReadWrite,
            0b111 => Self::ReadWriteExecute,
            _ => Self::ReservedNoAccess,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage1OverlayPermission {
    NoAccess,
    Read,
    Execute,
    ReadExecute,
    Write,
    ReadWrite,
    WriteExecute,
    ReadWriteExecute,
    ReservedNoAccess,
}

impl Stage1OverlayPermission {
    const fn from_raw(raw: u8) -> Self {
        match raw & 0b1111 {
            0b0000 => Self::NoAccess,
            0b0001 => Self::Read,
            0b0010 => Self::Execute,
            0b0011 => Self::ReadExecute,
            0b0100 => Self::Write,
            0b0101 => Self::ReadWrite,
            0b0110 => Self::WriteExecute,
            0b0111 => Self::ReadWriteExecute,
            _ => Self::ReservedNoAccess,
        }
    }
}

impl LeafAp {
    fn decode_single_privilege(self) -> DataRights {
        if self.bits() & 0b10 == 0 {
            DataRights::ReadWrite
        } else {
            DataRights::Read
        }
    }

    fn decode_two_privilege(self) -> (DataRights, DataRights) {
        let privileged = if self.bits() & 0b10 == 0 {
            DataRights::ReadWrite
        } else {
            DataRights::Read
        };
        let unprivileged = if self.bits() & 0b01 == 0 {
            DataRights::None
        } else {
            privileged
        };
        (privileged, unprivileged)
    }
}

impl TableAp {
    fn encode_single_privilege(
        limits: SinglePrivilegeTableRestrictions,
    ) -> Result<Self, AttrError> {
        Self::from_bits(match limits.data_limit {
            DataRights::ReadWrite => 0b00,
            DataRights::Read => 0b10,
            DataRights::None | DataRights::Write => return Err(AttrError::UnencodablePermissions),
        })
    }

    fn decode_single_privilege(
        self,
        execute_limit: bool,
    ) -> Result<SinglePrivilegeTableRestrictions, AttrError> {
        let data_limit = match self.bits() {
            0b00 => DataRights::ReadWrite,
            0b10 => DataRights::Read,
            bits => return Err(AttrError::InvalidTableAp(bits)),
        };
        Ok(SinglePrivilegeTableRestrictions {
            data_limit,
            execute_limit,
        })
    }

    fn encode_two_privilege(limits: TwoPrivilegeTableRestrictions) -> Result<Self, AttrError> {
        Self::from_bits(
            match (limits.privileged_data_limit, limits.unprivileged_data_limit) {
                (DataRights::ReadWrite, DataRights::ReadWrite) => 0b00,
                (DataRights::ReadWrite, DataRights::None) => 0b01,
                (DataRights::Read, DataRights::Read) => 0b10,
                (DataRights::Read, DataRights::None) => 0b11,
                _ => return Err(AttrError::UnencodablePermissions),
            },
        )
    }

    fn decode_two_privilege(
        self,
        privileged_execute_limit: bool,
        unprivileged_execute_limit: bool,
    ) -> TwoPrivilegeTableRestrictions {
        let (privileged_data_limit, unprivileged_data_limit) = match self.bits() {
            0b00 => (DataRights::ReadWrite, DataRights::ReadWrite),
            0b01 => (DataRights::ReadWrite, DataRights::None),
            0b10 => (DataRights::Read, DataRights::Read),
            _ => (DataRights::Read, DataRights::None),
        };
        TwoPrivilegeTableRestrictions {
            privileged_data_limit,
            unprivileged_data_limit,
            privileged_execute_limit,
            unprivileged_execute_limit,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawStage1DirectLeafPermissions {
    pub ap: LeafAp,
    pub privileged_execute_never: bool,
    pub unprivileged_execute_never: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1DirectEncoding<I = FourBit> {
    pub leaf: RawStage1DirectLeafPermissions,
    pub overlay: I,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage1PermissionEncoding<I = FourBit> {
    Direct(Stage1DirectEncoding<I>),
    Indirect(PermissionIndices<I>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawStage1TablePermissionLimits {
    pub ap_table: TableAp,
    pub privileged_execute_never_limit: bool,
    pub unprivileged_execute_never_limit: bool,
}

pub trait Stage1DirectPermissionModel: PrivilegeModel {
    fn decode_leaf(raw: RawStage1DirectLeafPermissions) -> Result<Stage1Permissions, AttrError>;

    fn encode_table(
        limits: Self::TableRestrictions,
    ) -> Result<RawStage1TablePermissionLimits, AttrError>;

    fn decode_table(
        raw: RawStage1TablePermissionLimits,
    ) -> Result<Self::TableRestrictions, AttrError>;
}

macro_rules! single_privilege_model {
    ($model:ty) => {
        impl Stage1DirectPermissionModel for $model {
            fn decode_leaf(
                raw: RawStage1DirectLeafPermissions,
            ) -> Result<Stage1Permissions, AttrError> {
                if raw.privileged_execute_never {
                    return Err(AttrError::UnencodablePermissions);
                }
                Ok(Stage1Permissions::new(
                    raw.ap.decode_single_privilege(),
                    DataRights::None,
                    !raw.unprivileged_execute_never,
                    false,
                    false,
                    false,
                ))
            }

            fn encode_table(
                value: Self::TableRestrictions,
            ) -> Result<RawStage1TablePermissionLimits, AttrError> {
                Ok(RawStage1TablePermissionLimits {
                    ap_table: TableAp::encode_single_privilege(value)?,
                    privileged_execute_never_limit: false,
                    unprivileged_execute_never_limit: !value.execute_limit,
                })
            }

            fn decode_table(
                raw: RawStage1TablePermissionLimits,
            ) -> Result<Self::TableRestrictions, AttrError> {
                if raw.privileged_execute_never_limit {
                    return Err(AttrError::UnencodablePermissions);
                }
                raw.ap_table
                    .decode_single_privilege(!raw.unprivileged_execute_never_limit)
            }
        }
    };
}

single_privilege_model!(El2Permissions);
single_privilege_model!(El3Permissions);
single_privilege_model!(SmmuPrivilegedStreamPermissions);

macro_rules! two_privilege_model {
    ($model:ty) => {
        impl Stage1DirectPermissionModel for $model {
            fn decode_leaf(
                raw: RawStage1DirectLeafPermissions,
            ) -> Result<Stage1Permissions, AttrError> {
                let (privileged_data, unprivileged_data) = raw.ap.decode_two_privilege();
                let mut privileged_execute = !raw.privileged_execute_never;
                // A writable mapping accessible at EL0 is never executable at
                // the privileged EL in the two-privilege translation regimes.
                if unprivileged_data == DataRights::ReadWrite {
                    privileged_execute = false;
                }
                Ok(Stage1Permissions::new(
                    privileged_data,
                    unprivileged_data,
                    privileged_execute,
                    !raw.unprivileged_execute_never,
                    false,
                    false,
                ))
            }

            fn encode_table(
                value: Self::TableRestrictions,
            ) -> Result<RawStage1TablePermissionLimits, AttrError> {
                Ok(RawStage1TablePermissionLimits {
                    ap_table: TableAp::encode_two_privilege(value)?,
                    privileged_execute_never_limit: !value.privileged_execute_limit,
                    unprivileged_execute_never_limit: !value.unprivileged_execute_limit,
                })
            }

            fn decode_table(
                raw: RawStage1TablePermissionLimits,
            ) -> Result<Self::TableRestrictions, AttrError> {
                Ok(TableAp::decode_two_privilege(
                    raw.ap_table,
                    !raw.privileged_execute_never_limit,
                    !raw.unprivileged_execute_never_limit,
                ))
            }
        }
    };
}

two_privilege_model!(El1And0Permissions);
two_privilege_model!(El2And0Permissions);
two_privilege_model!(SmmuStreamPermissions);

macro_rules! stage1_permission_codec {
    ($codec:ident, $interpretation:ty) => {
        impl<C, I, P> PermissionCodec<C, Stage1PermissionEncoding<I>> for $codec<P>
        where
            C: Stage1PermissionConfig,
            I: PermissionIndex,
            P: Stage1DirectPermissionModel,
        {
            type Permissions = Stage1Permissions;

            fn encode(
                config: &C,
                wanted: Self::Permissions,
            ) -> Result<Stage1PermissionEncoding<I>, AttrError> {
                let settings = config.stage1_permissions();
                match settings.base {
                    Stage1BasePermissions::Direct => {
                        let po_count = if settings.overlays.privileged.is_some()
                            || settings.overlays.unprivileged.is_some()
                        {
                            I::COUNT
                        } else {
                            1
                        };
                        for ap in 0..4 {
                            for pxn in [false, true] {
                                for uxn in [false, true] {
                                    let leaf = RawStage1DirectLeafPermissions {
                                        ap: LeafAp::from_bits(ap)?,
                                        privileged_execute_never: pxn,
                                        unprivileged_execute_never: uxn,
                                    };
                                    let Ok(base) = P::decode_leaf(leaf) else {
                                        continue;
                                    };
                                    for po in 0..po_count {
                                        let effective = settings.overlays.apply(base, po);
                                        if effective == Some(wanted) {
                                            return Ok(Stage1PermissionEncoding::Direct(
                                                Stage1DirectEncoding {
                                                    leaf,
                                                    overlay: I::new(po)?,
                                                },
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        Err(AttrError::UnencodablePermissions)
                    }
                    Stage1BasePermissions::Indirect(_) => Ok(Stage1PermissionEncoding::Indirect(
                        Stage1PermissionResolver::<C, I, $interpretation>::new(config)
                            .resolve(wanted)?,
                    )),
                }
            }

            fn decode(
                config: &C,
                encoding: Stage1PermissionEncoding<I>,
            ) -> Result<Self::Permissions, AttrError> {
                match (config.stage1_permissions().base, encoding) {
                    (Stage1BasePermissions::Direct, Stage1PermissionEncoding::Direct(raw)) => {
                        let base = P::decode_leaf(raw.leaf)?;
                        config
                            .stage1_permissions()
                            .overlays
                            .apply(base, raw.overlay.bits())
                            .ok_or(AttrError::UnencodablePermissions)
                    }
                    (
                        Stage1BasePermissions::Indirect(_),
                        Stage1PermissionEncoding::Indirect(indices),
                    ) => Stage1PermissionResolver::<C, I, $interpretation>::new(config)
                        .decode(indices),
                    _ => Err(AttrError::PermissionModeMismatch),
                }
            }
        }
    };
}

stage1_permission_codec!(PeStage1PermissionCodec, PeDescriptors);
stage1_permission_codec!(
    SmmuV2Stage1PermissionCodec,
    crate::descriptor::SmmuV2Descriptors
);
stage1_permission_codec!(
    SmmuV3Stage1PermissionCodec,
    crate::descriptor::SmmuV3Descriptors
);

pub(crate) trait Stage1IndirectPolicy: DescriptorInterpretation {
    fn decode_entry(register: u64, index: u8, gcs_implemented: bool) -> Stage1Access;

    fn base_pair_is_reserved(privileged: Stage1Access, unprivileged: Stage1Access) -> bool;
}

macro_rules! pe_indirect_policy {
    ($interpretation:ty) => {
        impl Stage1IndirectPolicy for $interpretation {
            fn decode_entry(register: u64, index: u8, gcs_implemented: bool) -> Stage1Access {
                decode_base(entry(register, index), gcs_implemented)
            }

            fn base_pair_is_reserved(privileged: Stage1Access, unprivileged: Stage1Access) -> bool {
                (privileged.execute || privileged.gcs) && (unprivileged.write || unprivileged.gcs)
            }
        }
    };
}

pe_indirect_policy!(PeDescriptors);
pe_indirect_policy!(SmmuV2Descriptors);

impl Stage1IndirectPolicy for SmmuV3Descriptors {
    fn decode_entry(register: u64, index: u8, _: bool) -> Stage1Access {
        decode_smmuv3_base(((register >> (u32::from(index) * 3)) & 0x7) as u8)
    }

    fn base_pair_is_reserved(_: Stage1Access, _: Stage1Access) -> bool {
        false
    }
}

pub struct Stage1PermissionResolver<'a, C: ?Sized, I = FourBit, D = PeDescriptors> {
    config: &'a C,
    index: core::marker::PhantomData<(I, D)>,
}

impl<'a, C, I, D> Stage1PermissionResolver<'a, C, I, D>
where
    C: Stage1PermissionConfig + ?Sized,
    I: super::PermissionIndex,
    D: Stage1IndirectPolicy,
{
    pub const fn new(config: &'a C) -> Self {
        Self {
            config,
            index: core::marker::PhantomData,
        }
    }

    pub fn resolve(&self, wanted: Stage1Permissions) -> Result<PermissionIndices<I>, AttrError> {
        let settings = self.config.stage1_permissions();
        let registers = match settings.base {
            Stage1BasePermissions::Indirect(registers) => registers,
            Stage1BasePermissions::Direct => {
                return Err(AttrError::PermissionIndirectionUnavailable);
            }
        };
        let po_count =
            if settings.overlays.privileged.is_some() || settings.overlays.unprivileged.is_some() {
                I::COUNT
            } else {
                1
            };

        for pi in 0..16 {
            for po in 0..po_count {
                if decode_effective::<D>(registers, settings.overlays, pi, po) == Some(wanted) {
                    return Ok(PermissionIndices {
                        pi: FourBit::new(pi)?,
                        po: I::new(po)?,
                    });
                }
            }
        }
        Err(AttrError::PermissionCombinationNotConfigured)
    }

    pub fn decode(&self, indices: PermissionIndices<I>) -> Result<Stage1Permissions, AttrError> {
        let settings = self.config.stage1_permissions();
        let registers = match settings.base {
            Stage1BasePermissions::Indirect(registers) => registers,
            Stage1BasePermissions::Direct => {
                return Err(AttrError::PermissionIndirectionUnavailable);
            }
        };
        decode_effective::<D>(
            registers,
            settings.overlays,
            indices.pi.bits(),
            indices.po.bits(),
        )
        .ok_or(AttrError::UnencodablePermissions)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Stage1Access {
    read: bool,
    write: bool,
    execute: bool,
    gcs: bool,
    apply_overlay: bool,
    wxn: bool,
}

fn decode_effective<D: Stage1IndirectPolicy>(
    registers: Stage1PermissionRegisters,
    overlays: Stage1PermissionOverlays,
    pi: u8,
    po: u8,
) -> Option<Stage1Permissions> {
    let privileged_base = D::decode_entry(registers.privileged, pi, registers.gcs_implemented);
    let unprivileged_base = registers
        .unprivileged
        .map(|base| D::decode_entry(base, pi, registers.gcs_implemented))
        .unwrap_or_else(no_bits);

    // This base-permission combination is reserved and removes all base
    // permissions before any permission overlay is applied.
    if D::base_pair_is_reserved(privileged_base, unprivileged_base) {
        return Some(Stage1Permissions::new(
            DataRights::None,
            DataRights::None,
            false,
            false,
            false,
            false,
        ));
    }

    let privileged = decode_pair::<D>(
        registers.privileged,
        overlays.privileged,
        pi,
        po,
        registers.gcs_implemented,
    );
    let unprivileged = registers
        .unprivileged
        .map(|base| {
            decode_pair::<D>(
                base,
                overlays.unprivileged,
                pi,
                po,
                registers.gcs_implemented,
            )
        })
        .unwrap_or_else(no_bits);

    if (privileged.execute || privileged.gcs) && (unprivileged.write || unprivileged.gcs) {
        return None;
    }

    Some(Stage1Permissions::new(
        data_access(privileged)?,
        data_access(unprivileged)?,
        privileged.execute,
        unprivileged.execute,
        privileged.gcs,
        unprivileged.gcs,
    ))
}

fn decode_pair<D: Stage1IndirectPolicy>(
    base_register: u64,
    overlay: Option<u64>,
    pi: u8,
    po: u8,
    gcs_implemented: bool,
) -> Stage1Access {
    let mut base = D::decode_entry(base_register, pi, gcs_implemented);
    match overlay {
        Some(overlay) => apply_overlay(base, entry(overlay, po)),
        None => {
            if base.wxn && base.write {
                base.execute = false;
            }
            base
        }
    }
}

fn decode_base(raw: u8, gcs_implemented: bool) -> Stage1Access {
    use Stage1BasePermission::*;

    let (read, write, execute, gcs, apply_overlay, wxn) = match Stage1BasePermission::from_raw(raw)
    {
        NoAccessApplyOverlay | ReservedNoAccessApplyOverlay => {
            (false, false, false, false, true, false)
        }
        ReadApplyOverlay => (true, false, false, false, true, false),
        ExecuteApplyOverlay => (false, false, true, false, true, false),
        ReadExecuteApplyOverlay => (true, false, true, false, true, false),
        ReadWriteApplyOverlay => (true, true, false, false, true, false),
        ReadWriteExecuteApplyOverlayWithWxn => (true, true, true, false, true, true),
        ReadWriteExecuteApplyOverlay => (true, true, true, false, true, false),
        ReadNoOverlay => (true, false, false, false, false, false),
        ReadGcsNoOverlay if gcs_implemented => (true, false, false, true, false, false),
        ReadGcsNoOverlay => (false, false, false, false, false, false),
        ReadExecuteNoOverlay => (true, false, true, false, false, false),
        ReservedNoAccessNoOverlay => (false, false, false, false, false, false),
        ReadWriteNoOverlay => (true, true, false, false, false, false),
        ReadWriteExecuteNoOverlay => (true, true, true, false, false, false),
    };

    Stage1Access {
        read,
        write,
        execute,
        gcs,
        apply_overlay,
        wxn,
    }
}

fn apply_overlay(base: Stage1Access, raw: u8) -> Stage1Access {
    if !base.apply_overlay {
        return base;
    }

    let (read, mut write, execute) = match Stage1OverlayPermission::from_raw(raw) {
        Stage1OverlayPermission::NoAccess | Stage1OverlayPermission::ReservedNoAccess => {
            (false, false, false)
        }
        Stage1OverlayPermission::Read => (true, false, false),
        Stage1OverlayPermission::Execute => (false, false, true),
        Stage1OverlayPermission::ReadExecute => (true, false, true),
        Stage1OverlayPermission::Write => (false, true, false),
        Stage1OverlayPermission::ReadWrite => (true, true, false),
        Stage1OverlayPermission::WriteExecute => (false, true, true),
        Stage1OverlayPermission::ReadWriteExecute => (true, true, true),
    };

    if base.wxn && execute {
        write = false;
    }

    Stage1Access {
        read: base.read && read,
        write: base.write && write,
        execute: base.execute && execute,
        gcs: base.gcs,
        apply_overlay: false,
        wxn: false,
    }
}

fn apply_effective_overlay(base: Stage1Access, overlay: Option<u64>, po: u8) -> Stage1Access {
    overlay.map_or(base, |register| apply_overlay(base, entry(register, po)))
}

const fn no_bits() -> Stage1Access {
    Stage1Access {
        read: false,
        write: false,
        execute: false,
        gcs: false,
        apply_overlay: false,
        wxn: false,
    }
}

const fn data_access(bits: Stage1Access) -> Option<DataRights> {
    Some(DataRights::from_read_write(bits.read, bits.write))
}

fn entry(register: u64, index: u8) -> u8 {
    ((register >> (u32::from(index) * 4)) & 0xf) as u8
}

fn decode_smmuv3_base(raw: u8) -> Stage1Access {
    use SmmuV3Stage1BasePermission::*;
    let (read, write, execute) = match SmmuV3Stage1BasePermission::from_raw(raw) {
        NoAccess | ReservedNoAccess => (false, false, false),
        ReadOnly => (true, false, false),
        ExecuteOnly => (false, false, true),
        ReadExecute => (true, false, true),
        ReadWrite => (true, true, false),
        ReadWriteExecute => (true, true, true),
    };
    Stage1Access {
        read,
        write,
        execute,
        gcs: false,
        apply_overlay: false,
        wxn: false,
    }
}
