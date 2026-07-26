use crate::attrs::{
    AttrError, FixedNonSecurePas, FixedRealmIpaPas, RealmOrNonSecurePa, RealmOrNonSecurePaPas,
    RootExtendedPa, RootExtendedPas, SecureSelectablePa, SecureSelectablePas, Stage1PasModel,
};

use super::PasConfig;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawStage1LeafPas {
    pub ns: bool,
    pub nse: bool,
}

pub trait Stage1PasResolver: Stage1PasModel {
    const USES_NSE: bool;
    const USES_NSTABLE: bool;

    fn resolve_leaf(value: Self::LeafAttr) -> Result<RawStage1LeafPas, AttrError>;
    fn decode_leaf(raw: RawStage1LeafPas) -> Result<Self::LeafAttr, AttrError>;

    fn resolve_table(value: Self::TableAttr) -> Result<Option<bool>, AttrError>;
    fn decode_table(ns_table: bool) -> Result<Self::TableAttr, AttrError>;
}

impl Stage1PasResolver for FixedNonSecurePas {
    const USES_NSE: bool = false;
    const USES_NSTABLE: bool = false;
    fn resolve_leaf(_: ()) -> Result<RawStage1LeafPas, AttrError> {
        Ok(RawStage1LeafPas::default())
    }
    fn decode_leaf(raw: RawStage1LeafPas) -> Result<(), AttrError> {
        if raw == RawStage1LeafPas::default() {
            Ok(())
        } else {
            Err(AttrError::InvalidOutputAddressSpace)
        }
    }
    fn resolve_table(_: ()) -> Result<Option<bool>, AttrError> {
        Ok(None)
    }
    fn decode_table(ns_table: bool) -> Result<(), AttrError> {
        if ns_table {
            Err(AttrError::InvalidOutputAddressSpace)
        } else {
            Ok(())
        }
    }
}

impl Stage1PasResolver for FixedRealmIpaPas {
    const USES_NSE: bool = false;
    const USES_NSTABLE: bool = false;
    fn resolve_leaf(_: ()) -> Result<RawStage1LeafPas, AttrError> {
        Ok(RawStage1LeafPas::default())
    }
    fn decode_leaf(raw: RawStage1LeafPas) -> Result<(), AttrError> {
        if raw == RawStage1LeafPas::default() {
            Ok(())
        } else {
            Err(AttrError::InvalidOutputAddressSpace)
        }
    }
    fn resolve_table(_: ()) -> Result<Option<bool>, AttrError> {
        Ok(None)
    }
    fn decode_table(ns_table: bool) -> Result<(), AttrError> {
        if ns_table {
            Err(AttrError::InvalidOutputAddressSpace)
        } else {
            Ok(())
        }
    }
}

impl Stage1PasResolver for RealmOrNonSecurePaPas {
    const USES_NSE: bool = false;
    const USES_NSTABLE: bool = false;
    fn resolve_leaf(value: RealmOrNonSecurePa) -> Result<RawStage1LeafPas, AttrError> {
        Ok(RawStage1LeafPas {
            ns: matches!(value, RealmOrNonSecurePa::NonSecure),
            nse: false,
        })
    }
    fn decode_leaf(raw: RawStage1LeafPas) -> Result<RealmOrNonSecurePa, AttrError> {
        if raw.nse {
            return Err(AttrError::InvalidOutputAddressSpace);
        }
        Ok(if raw.ns {
            RealmOrNonSecurePa::NonSecure
        } else {
            RealmOrNonSecurePa::Realm
        })
    }
    fn resolve_table(_: ()) -> Result<Option<bool>, AttrError> {
        Ok(None)
    }
    fn decode_table(ns_table: bool) -> Result<(), AttrError> {
        if ns_table {
            Err(AttrError::InvalidOutputAddressSpace)
        } else {
            Ok(())
        }
    }
}

impl Stage1PasResolver for RootExtendedPas {
    const USES_NSE: bool = true;
    const USES_NSTABLE: bool = false;
    fn resolve_leaf(value: RootExtendedPa) -> Result<RawStage1LeafPas, AttrError> {
        let (ns, nse) = match value {
            RootExtendedPa::Secure => (false, false),
            RootExtendedPa::NonSecure => (true, false),
            RootExtendedPa::Root => (false, true),
            RootExtendedPa::Realm => (true, true),
        };
        Ok(RawStage1LeafPas { ns, nse })
    }
    fn decode_leaf(raw: RawStage1LeafPas) -> Result<RootExtendedPa, AttrError> {
        Ok(match (raw.ns, raw.nse) {
            (false, false) => RootExtendedPa::Secure,
            (true, false) => RootExtendedPa::NonSecure,
            (false, true) => RootExtendedPa::Root,
            (true, true) => RootExtendedPa::Realm,
        })
    }
    fn resolve_table(_: ()) -> Result<Option<bool>, AttrError> {
        Ok(None)
    }
    fn decode_table(ns_table: bool) -> Result<(), AttrError> {
        if ns_table {
            Err(AttrError::InvalidOutputAddressSpace)
        } else {
            Ok(())
        }
    }
}

impl Stage1PasResolver for SecureSelectablePas {
    const USES_NSE: bool = false;
    const USES_NSTABLE: bool = true;
    fn resolve_leaf(value: SecureSelectablePa) -> Result<RawStage1LeafPas, AttrError> {
        Ok(RawStage1LeafPas {
            ns: matches!(value, SecureSelectablePa::NonSecure),
            nse: false,
        })
    }
    fn decode_leaf(raw: RawStage1LeafPas) -> Result<SecureSelectablePa, AttrError> {
        if raw.nse {
            return Err(AttrError::InvalidOutputAddressSpace);
        }
        Ok(if raw.ns {
            SecureSelectablePa::NonSecure
        } else {
            SecureSelectablePa::Secure
        })
    }
    fn resolve_table(value: SecureSelectablePa) -> Result<Option<bool>, AttrError> {
        Ok(Some(matches!(value, SecureSelectablePa::NonSecure)))
    }
    fn decode_table(ns_table: bool) -> Result<SecureSelectablePa, AttrError> {
        Ok(if ns_table {
            SecureSelectablePa::NonSecure
        } else {
            SecureSelectablePa::Secure
        })
    }
}

pub const fn resolve_fixed_nonsecure_stage2_pas(_: ()) -> bool {
    false
}

pub const fn resolve_realm_stage2_pas(value: RealmOrNonSecurePa) -> bool {
    matches!(value, RealmOrNonSecurePa::NonSecure)
}

pub const fn decode_realm_stage2_pas(ns: bool) -> RealmOrNonSecurePa {
    if ns {
        RealmOrNonSecurePa::NonSecure
    } else {
        RealmOrNonSecurePa::Realm
    }
}

pub fn resolve_configured_secure_stage2_pas<C>(
    config: &C,
    requested: SecureSelectablePa,
) -> Result<bool, AttrError>
where
    C: PasConfig<Pas = SecureSelectablePa>,
{
    if config.configured_output_pas() == requested {
        Ok(false)
    } else {
        Err(AttrError::InvalidOutputAddressSpace)
    }
}

pub fn decode_configured_secure_stage2_pas<C>(
    config: &C,
    descriptor_ns: bool,
) -> Result<SecureSelectablePa, AttrError>
where
    C: PasConfig<Pas = SecureSelectablePa>,
{
    if descriptor_ns {
        Err(AttrError::InvalidOutputAddressSpace)
    } else {
        Ok(config.configured_output_pas())
    }
}
