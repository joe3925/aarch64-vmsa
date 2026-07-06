use core::fmt::Debug;

use crate::features::VmsaFeatures;
use crate::translation_regime::{IpaSpace, TranslationSpace};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum OutputAddressSpace {
    NonSecure,
    Secure,
    Realm,
    Root,
}

pub trait Stage1PasModel: Copy + 'static {
    type LeafAttr: Copy + Debug + Eq + PartialEq;
    type TableAttr: Copy + Debug + Eq + PartialEq;

    const SPACE: TranslationSpace;
    const REQUIRED_FEATURES: VmsaFeatures;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedNonSecurePas;

impl Stage1PasModel for FixedNonSecurePas {
    type LeafAttr = ();
    type TableAttr = ();

    const SPACE: TranslationSpace = TranslationSpace::NonSecure;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureSelectablePas;

impl Stage1PasModel for SecureSelectablePas {
    type LeafAttr = OutputAddressSpace;
    type TableAttr = OutputAddressSpace;

    const SPACE: TranslationSpace = TranslationSpace::Secure;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_secure_state();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmPas;

impl Stage1PasModel for RealmPas {
    type LeafAttr = OutputAddressSpace;
    type TableAttr = OutputAddressSpace;

    const SPACE: TranslationSpace = TranslationSpace::Realm;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_rme();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootPas;

impl Stage1PasModel for RootPas {
    type LeafAttr = OutputAddressSpace;
    type TableAttr = OutputAddressSpace;

    const SPACE: TranslationSpace = TranslationSpace::Root;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_rme();
}

pub trait Stage2PasContext: Copy + 'static {
    const SPACE: TranslationSpace;
    const IPA_SPACE: IpaSpace;
    const REQUIRED_FEATURES: VmsaFeatures;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonSecureIpaContext;

impl Stage2PasContext for NonSecureIpaContext {
    const SPACE: TranslationSpace = TranslationSpace::NonSecure;
    const IPA_SPACE: IpaSpace = IpaSpace::NonSecure;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureIpaContext;

impl Stage2PasContext for SecureIpaContext {
    const SPACE: TranslationSpace = TranslationSpace::Secure;
    const IPA_SPACE: IpaSpace = IpaSpace::Secure;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_secure_state().with_sel2();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureNonSecureIpaContext;

impl Stage2PasContext for SecureNonSecureIpaContext {
    const SPACE: TranslationSpace = TranslationSpace::Secure;
    const IPA_SPACE: IpaSpace = IpaSpace::NonSecure;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_secure_state().with_sel2();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmIpaContext;

impl Stage2PasContext for RealmIpaContext {
    const SPACE: TranslationSpace = TranslationSpace::Realm;
    const IPA_SPACE: IpaSpace = IpaSpace::Realm;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_rme();
}
