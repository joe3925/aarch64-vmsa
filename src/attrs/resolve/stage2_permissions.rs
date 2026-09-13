use super::{
    PeStage2PermissionCodec, PermissionCodec, PermissionIndex, SmmuV2Stage2PermissionCodec,
    SmmuV3Stage2PermissionCodec, Stage2PermissionConfig,
};
use crate::attrs::{
    AttrError, DataRights, ExecuteRights, FourBit, PermissionIndices, Stage2Ap, Stage2ExecuteNever,
    Stage2PermissionModel, Stage2Permissions, TopLevelRequirements,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2PermissionRegisters {
    pub s2pir_el2: u64,
}

impl Stage2PermissionRegisters {
    fn entry(self, index: u8) -> Stage2IndirectEntry {
        Stage2IndirectEntry(((self.s2pir_el2 >> (u32::from(index) * 4)) & 0xf) as u8)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2BasePermissions {
    Direct,
    Indirect(Stage2PermissionRegisters),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2PermissionSettings {
    pub base: Stage2BasePermissions,
    pub s2por_el1: Option<u64>,
}

impl Stage2PermissionSettings {
    pub const fn direct() -> Self {
        Self {
            base: Stage2BasePermissions::Direct,
            s2por_el1: None,
        }
    }

    fn overlay_entry(self, index: u8) -> Option<Stage2IndirectEntry> {
        self.s2por_el1
            .map(|register| Stage2IndirectEntry(((register >> (u32::from(index) * 4)) & 0xf) as u8))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stage2IndirectEntry(u8);

impl Stage2IndirectEntry {
    const fn decode(self) -> Stage2Permissions {
        let execute =
            ExecuteRights::from_privileged_unprivileged(self.0 & 0b0010 != 0, self.0 & 0b0001 != 0);
        match self.0 {
            0b0000 | 0b0001 | 0b0101 => Stage2Permissions::no_access(),
            0b0010 => Stage2Permissions::mostly_read_only(TopLevelRequirements::NONE),
            0b0011 => Stage2Permissions::mostly_read_only(TopLevelRequirements::TOP_LEVEL1),
            0b0100 => Stage2Permissions::special_write_only(),
            0b0110 => Stage2Permissions::mostly_read_only(TopLevelRequirements::TOP_LEVEL0),
            0b0111 => Stage2Permissions::mostly_read_only(TopLevelRequirements::BOTH),
            0b1000..=0b1011 => Stage2Permissions::direct(DataRights::Read, execute),
            _ => Stage2Permissions::direct(DataRights::ReadWrite, execute),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2DirectEncoding {
    pub access: Stage2Ap,
    pub execute_never: Stage2ExecuteNever,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2PermissionEncoding<I = FourBit> {
    Direct(Stage2DirectEncoding),
    Indirect(PermissionIndices<I>),
}

impl Stage2DirectEncoding {
    pub fn decode(self, xnx: bool) -> Result<Stage2Permissions, AttrError> {
        let data = match self.access.bits() {
            0b00 => DataRights::None,
            0b01 => DataRights::Read,
            0b10 => DataRights::Write,
            0b11 => DataRights::ReadWrite,
            bits => return Err(AttrError::InvalidStage2Permission(bits)),
        };
        let execute = if xnx {
            match self.execute_never.bits() {
                0b00 => ExecuteRights::Both,
                0b01 => ExecuteRights::Unprivileged,
                0b10 => ExecuteRights::Neither,
                0b11 => ExecuteRights::Privileged,
                _ => return Err(AttrError::InvalidStage2ExecuteNever),
            }
        } else {
            match self.execute_never.bits() {
                0b00 => ExecuteRights::Both,
                0b10 => ExecuteRights::Neither,
                _ => return Err(AttrError::InvalidStage2ExecuteNever),
            }
        };
        Ok(Stage2Permissions::direct(data, execute))
    }

    pub fn encode(wanted: Stage2Permissions, xnx: bool) -> Result<Self, AttrError> {
        for ap in 0..4 {
            for xn in 0..4 {
                let candidate = Self {
                    access: Stage2Ap::from_bits(ap)?,
                    execute_never: Stage2ExecuteNever::from_bits(xn)?,
                };
                if candidate.decode(xnx) == Ok(wanted) {
                    return Ok(candidate);
                }
            }
        }
        Err(AttrError::UnencodablePermissions)
    }
}

macro_rules! stage2_permission_codec {
    ($codec:ident) => {
        impl<C, I, P> PermissionCodec<C, Stage2PermissionEncoding<I>> for $codec<P>
        where
            C: Stage2PermissionConfig,
            I: PermissionIndex,
            P: Stage2PermissionModel,
        {
            type Permissions = Stage2Permissions;

            fn encode(
                config: &C,
                wanted: Self::Permissions,
            ) -> Result<Stage2PermissionEncoding<I>, AttrError> {
                match config.stage2_permissions().base {
                    Stage2BasePermissions::Direct => Ok(Stage2PermissionEncoding::Direct(
                        Stage2DirectEncoding::encode(wanted, P::XNX)?,
                    )),
                    Stage2BasePermissions::Indirect(_) => Ok(Stage2PermissionEncoding::Indirect(
                        Stage2PermissionResolver::<C, I>::new(config).resolve(wanted)?,
                    )),
                }
            }

            fn decode(
                config: &C,
                encoding: Stage2PermissionEncoding<I>,
            ) -> Result<Self::Permissions, AttrError> {
                match (config.stage2_permissions().base, encoding) {
                    (Stage2BasePermissions::Direct, Stage2PermissionEncoding::Direct(raw)) => {
                        raw.decode(P::XNX)
                    }
                    (
                        Stage2BasePermissions::Indirect(_),
                        Stage2PermissionEncoding::Indirect(indices),
                    ) => Stage2PermissionResolver::<C, I>::new(config).decode(indices),
                    _ => Err(AttrError::PermissionModeMismatch),
                }
            }
        }
    };
}

stage2_permission_codec!(PeStage2PermissionCodec);
stage2_permission_codec!(SmmuV3Stage2PermissionCodec);

impl<C, P> PermissionCodec<C, Stage2DirectEncoding> for SmmuV2Stage2PermissionCodec<P>
where
    P: Stage2PermissionModel,
{
    type Permissions = Stage2Permissions;

    fn encode(_: &C, wanted: Self::Permissions) -> Result<Stage2DirectEncoding, AttrError> {
        Stage2DirectEncoding::encode(wanted, false)
    }

    fn decode(_: &C, encoding: Stage2DirectEncoding) -> Result<Self::Permissions, AttrError> {
        encoding.decode(false)
    }
}

pub struct Stage2PermissionResolver<'a, C: ?Sized, I = FourBit> {
    config: &'a C,
    index: core::marker::PhantomData<I>,
}

impl<'a, C: Stage2PermissionConfig + ?Sized, I: PermissionIndex>
    Stage2PermissionResolver<'a, C, I>
{
    pub const fn new(config: &'a C) -> Self {
        Self {
            config,
            index: core::marker::PhantomData,
        }
    }

    pub fn resolve(&self, wanted: Stage2Permissions) -> Result<PermissionIndices<I>, AttrError> {
        for pi in 0..16 {
            for po in 0..self.overlay_count() {
                if self.decode_indices(pi, po)? == wanted {
                    return Ok(PermissionIndices {
                        pi: FourBit::new(pi)?,
                        po: I::new(po)?,
                    });
                }
            }
        }
        Err(AttrError::PermissionCombinationNotConfigured)
    }

    pub fn decode(&self, indices: PermissionIndices<I>) -> Result<Stage2Permissions, AttrError> {
        self.decode_indices(indices.pi.bits(), indices.po.bits())
    }

    fn settings(&self) -> Result<(Stage2PermissionSettings, Stage2PermissionRegisters), AttrError> {
        let settings = self.config.stage2_permissions();
        match settings.base {
            Stage2BasePermissions::Indirect(registers) => Ok((settings, registers)),
            Stage2BasePermissions::Direct => Err(AttrError::PermissionIndirectionUnavailable),
        }
    }

    fn overlay_count(&self) -> u8 {
        if self.config.stage2_permissions().s2por_el1.is_some() {
            I::COUNT
        } else {
            1
        }
    }

    fn decode_indices(&self, pi: u8, po: u8) -> Result<Stage2Permissions, AttrError> {
        let (settings, registers) = self.settings()?;
        let base = registers.entry(pi).decode();
        Ok(settings
            .overlay_entry(po)
            .map_or(base, |overlay| base.intersection(overlay.decode())))
    }
}
