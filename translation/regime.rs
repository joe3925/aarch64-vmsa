use core::marker::PhantomData;

use crate::arch::VmsaFeatures;
use crate::attrs::{
    AttributeProfile, El1And0Permissions, El2And0Permissions, El2Permissions, El3Permissions,
    FixedNonSecurePas, NonSecureIpaContext, RealmIpaContext, RealmPas, RootPas, SecureIpaContext,
    SecureNonSecureIpaContext, SecureSelectablePas, Stage1Profile, Stage2PermissionModel,
    Stage2Permissions, Stage2Profile,
};
use crate::translation::{Stage1Walk, Stage2Walk, TranslationWalkProfile};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RegimeOwner {
    El1,
    El2,
    El3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TranslationSpace {
    NonSecure,
    Secure,
    Root,
    Realm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum IpaSpace {
    NonSecure,
    Secure,
    Realm,
}

pub trait TranslationRegime: Copy + 'static {
    type WalkProfile: TranslationWalkProfile;
    type AttrProfile: AttributeProfile<<Self::WalkProfile as TranslationWalkProfile>::Stage>;

    const OWNER: RegimeOwner = <Self::AttrProfile as AttributeProfile<
        <Self::WalkProfile as TranslationWalkProfile>::Stage,
    >>::OWNER;
    const SPACE: TranslationSpace = <Self::AttrProfile as AttributeProfile<
        <Self::WalkProfile as TranslationWalkProfile>::Stage,
    >>::SPACE;
    const IPA_SPACE: Option<IpaSpace> = <Self::AttrProfile as AttributeProfile<
        <Self::WalkProfile as TranslationWalkProfile>::Stage,
    >>::IPA_SPACE;
    const SUPPORTS_EL0: bool = <Self::AttrProfile as AttributeProfile<
        <Self::WalkProfile as TranslationWalkProfile>::Stage,
    >>::SUPPORTS_EL0;
    const HAS_TTBR1: bool = <Self::AttrProfile as AttributeProfile<
        <Self::WalkProfile as TranslationWalkProfile>::Stage,
    >>::HAS_TTBR1;
    const FEATURES: VmsaFeatures = <Self::AttrProfile as AttributeProfile<
        <Self::WalkProfile as TranslationWalkProfile>::Stage,
    >>::REQUIRED_FEATURES;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonSecureEl1Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl1Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmEl1Stage1;

impl TranslationRegime for NonSecureEl1Stage1 {
    type WalkProfile = Stage1Walk;
    type AttrProfile = Stage1Profile<El1And0Permissions, FixedNonSecurePas>;
}

impl TranslationRegime for SecureEl1Stage1 {
    type WalkProfile = Stage1Walk;
    type AttrProfile = Stage1Profile<El1And0Permissions, SecureSelectablePas>;
}

impl TranslationRegime for RealmEl1Stage1 {
    type WalkProfile = Stage1Walk;
    type AttrProfile = Stage1Profile<El1And0Permissions, RealmPas>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonSecureEl2Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl2Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmEl2Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonSecureEl2HostStage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl2HostStage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmEl2HostStage1;

impl TranslationRegime for NonSecureEl2Stage1 {
    type WalkProfile = Stage1Walk;
    type AttrProfile = Stage1Profile<El2Permissions, FixedNonSecurePas>;
}

impl TranslationRegime for SecureEl2Stage1 {
    type WalkProfile = Stage1Walk;
    type AttrProfile = Stage1Profile<El2Permissions, SecureSelectablePas>;
}

impl TranslationRegime for RealmEl2Stage1 {
    type WalkProfile = Stage1Walk;
    type AttrProfile = Stage1Profile<El2Permissions, RealmPas>;
}

impl TranslationRegime for NonSecureEl2HostStage1 {
    type WalkProfile = Stage1Walk;
    type AttrProfile = Stage1Profile<El2And0Permissions, FixedNonSecurePas>;
}

impl TranslationRegime for SecureEl2HostStage1 {
    type WalkProfile = Stage1Walk;
    type AttrProfile = Stage1Profile<El2And0Permissions, SecureSelectablePas>;
}

impl TranslationRegime for RealmEl2HostStage1 {
    type WalkProfile = Stage1Walk;
    type AttrProfile = Stage1Profile<El2And0Permissions, RealmPas>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonSecureEl2Stage2<P = Stage2Permissions>(PhantomData<fn() -> P>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl2SecureIpaStage2<P = Stage2Permissions>(PhantomData<fn() -> P>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl2NonSecureIpaStage2<P = Stage2Permissions>(PhantomData<fn() -> P>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmEl2Stage2<P = Stage2Permissions>(PhantomData<fn() -> P>);

impl<P> TranslationRegime for NonSecureEl2Stage2<P>
where
    P: Stage2PermissionModel,
{
    type WalkProfile = Stage2Walk;
    type AttrProfile = Stage2Profile<P, NonSecureIpaContext>;
}

impl<P> TranslationRegime for SecureEl2SecureIpaStage2<P>
where
    P: Stage2PermissionModel,
{
    type WalkProfile = Stage2Walk;
    type AttrProfile = Stage2Profile<P, SecureIpaContext>;
}

impl<P> TranslationRegime for SecureEl2NonSecureIpaStage2<P>
where
    P: Stage2PermissionModel,
{
    type WalkProfile = Stage2Walk;
    type AttrProfile = Stage2Profile<P, SecureNonSecureIpaContext>;
}

impl<P> TranslationRegime for RealmEl2Stage2<P>
where
    P: Stage2PermissionModel,
{
    type WalkProfile = Stage2Walk;
    type AttrProfile = Stage2Profile<P, RealmIpaContext>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootEl3Stage1;

impl TranslationRegime for RootEl3Stage1 {
    type WalkProfile = Stage1Walk;
    type AttrProfile = Stage1Profile<El3Permissions, RootPas>;
}
