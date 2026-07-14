use core::fmt::Debug;

use crate::arch::{FeatureRequirements, SecurityStates};

pub trait PasModel: Copy + 'static {
    const REQUIRED_FEATURES: FeatureRequirements;
}

pub trait Stage1PasModel: PasModel {
    type LeafAttr: Copy + Debug + Eq + PartialEq;
    type TableAttr: Copy + Debug + Eq + PartialEq;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedNonSecurePas;
impl PasModel for FixedNonSecurePas {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
}
impl Stage1PasModel for FixedNonSecurePas {
    type LeafAttr = ();
    type TableAttr = ();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureSelectablePa {
    Secure,
    NonSecure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureSelectablePas;
impl PasModel for SecureSelectablePas {
    const REQUIRED_FEATURES: FeatureRequirements =
        FeatureRequirements::NONE.with_security_state(SecurityStates::SECURE);
}
impl Stage1PasModel for SecureSelectablePas {
    type LeafAttr = SecureSelectablePa;
    type TableAttr = SecureSelectablePa;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedRealmIpaPas;
impl PasModel for FixedRealmIpaPas {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .with_rme()
        .with_security_state(SecurityStates::REALM);
}
impl Stage1PasModel for FixedRealmIpaPas {
    type LeafAttr = ();
    type TableAttr = ();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmOrNonSecurePa {
    Realm,
    NonSecure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmOrNonSecurePaPas;
impl PasModel for RealmOrNonSecurePaPas {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .with_rme()
        .with_security_state(SecurityStates::REALM);
}
impl Stage1PasModel for RealmOrNonSecurePaPas {
    type LeafAttr = RealmOrNonSecurePa;
    type TableAttr = ();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootExtendedPa {
    Secure,
    NonSecure,
    Root,
    Realm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootExtendedPas;
impl PasModel for RootExtendedPas {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .with_rme()
        .with_el3()
        .with_security_state(SecurityStates::ROOT);
}
impl Stage1PasModel for RootExtendedPas {
    type LeafAttr = RootExtendedPa;
    type TableAttr = ();
}

pub trait Stage2PasContext: PasModel {
    type OutputAddressSpaceAttr: Copy + Debug + Eq + PartialEq;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonSecureIpaContext;
impl PasModel for NonSecureIpaContext {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
}
impl Stage2PasContext for NonSecureIpaContext {
    type OutputAddressSpaceAttr = ();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureIpaContext;
impl PasModel for SecureIpaContext {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .with_el2()
        .with_sel2()
        .with_security_state(SecurityStates::SECURE);
}
impl Stage2PasContext for SecureIpaContext {
    type OutputAddressSpaceAttr = SecureSelectablePa;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureNonSecureIpaContext;
impl PasModel for SecureNonSecureIpaContext {
    const REQUIRED_FEATURES: FeatureRequirements = SecureIpaContext::REQUIRED_FEATURES;
}
impl Stage2PasContext for SecureNonSecureIpaContext {
    type OutputAddressSpaceAttr = SecureSelectablePa;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmIpaContext;
impl PasModel for RealmIpaContext {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .with_rme()
        .with_security_state(SecurityStates::REALM);
}
impl Stage2PasContext for RealmIpaContext {
    type OutputAddressSpaceAttr = RealmOrNonSecurePa;
}
