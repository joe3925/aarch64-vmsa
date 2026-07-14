use core::marker::PhantomData;

use crate::address::TranslationGranule;
use crate::arch::{FeatureRequirements, VmsaFeatures};
use crate::attrs::{
    El1And0Permissions, El2And0Permissions, El2Permissions, El3Permissions, FixedNonSecurePas,
    FixedRealmIpaPas, NonSecureIpaContext, PasModel, PrivilegeModel, RealmIpaContext,
    RealmOrNonSecurePaPas, RootExtendedPas, SecureIpaContext, SecureNonSecureIpaContext,
    SecureSelectablePas, Stage2PermissionModel, Stage2Permissions,
};
use crate::descriptor::{DescriptorFormat, DescriptorLayout, HasLayout};
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
    type PasModel: PasModel;

    const OWNER: RegimeOwner;
    const SPACE: TranslationSpace;
    const REQUIRED_FEATURES: FeatureRequirements;
}

pub trait Stage1Regime: TranslationRegime {
    type PrivilegeModel: PrivilegeModel;

    const SUPPORTS_EL0: bool;
    const HAS_TTBR1: bool;
}

pub trait Stage2Regime: TranslationRegime {
    type PermissionModel: Stage2PermissionModel;

    const IPA_SPACE: IpaSpace;
}

pub type StageOf<R> = <<R as TranslationRegime>::WalkProfile as TranslationWalkProfile>::Stage;
pub type LayoutOf<F, R, G> = <F as HasLayout<StageOf<R>, G>>::Layout;
pub type LeafFieldsOf<F, R, G> =
    <LayoutOf<F, R, G> as DescriptorLayout<F, StageOf<R>, G>>::LeafFields;
pub type TableFieldsOf<F, R, G> =
    <LayoutOf<F, R, G> as DescriptorLayout<F, StageOf<R>, G>>::TableFields;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegimeValidationError {
    UnsupportedFeaturesOrSecurityState,
}

pub fn validate_regime<R: TranslationRegime>(
    features: &VmsaFeatures,
) -> Result<(), RegimeValidationError> {
    if features.verify(R::REQUIRED_FEATURES) {
        Ok(())
    } else {
        Err(RegimeValidationError::UnsupportedFeaturesOrSecurityState)
    }
}

pub fn validate_regime_format<F, R, G>(features: &VmsaFeatures) -> Result<(), RegimeValidationError>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    let required = R::REQUIRED_FEATURES
        .union(<LayoutOf<F, R, G> as DescriptorLayout<F, StageOf<R>, G>>::REQUIRED_FEATURES);
    if features.verify(required) {
        Ok(())
    } else {
        Err(RegimeValidationError::UnsupportedFeaturesOrSecurityState)
    }
}

macro_rules! stage1_regime {
    ($name:ident, $owner:expr, $space:expr, $permissions:ty, $pas:ty) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name;
        impl TranslationRegime for $name {
            type WalkProfile = Stage1Walk;
            type PasModel = $pas;
            const OWNER: RegimeOwner = $owner;
            const SPACE: TranslationSpace = $space;
            const REQUIRED_FEATURES: FeatureRequirements =
                <$permissions as PrivilegeModel>::REQUIRED_FEATURES
                    .union(<$pas as PasModel>::REQUIRED_FEATURES);
        }
        impl Stage1Regime for $name {
            type PrivilegeModel = $permissions;
            const SUPPORTS_EL0: bool = <$permissions as PrivilegeModel>::SUPPORTS_EL0;
            const HAS_TTBR1: bool = <$permissions as PrivilegeModel>::HAS_TTBR1;
        }
    };
}

stage1_regime!(
    NonSecureEl1Stage1,
    RegimeOwner::El1,
    TranslationSpace::NonSecure,
    El1And0Permissions,
    FixedNonSecurePas
);
stage1_regime!(
    SecureEl1Stage1,
    RegimeOwner::El1,
    TranslationSpace::Secure,
    El1And0Permissions,
    SecureSelectablePas
);
stage1_regime!(
    RealmEl1Stage1,
    RegimeOwner::El1,
    TranslationSpace::Realm,
    El1And0Permissions,
    FixedRealmIpaPas
);
stage1_regime!(
    NonSecureEl2Stage1,
    RegimeOwner::El2,
    TranslationSpace::NonSecure,
    El2Permissions,
    FixedNonSecurePas
);
stage1_regime!(
    SecureEl2Stage1,
    RegimeOwner::El2,
    TranslationSpace::Secure,
    El2Permissions,
    SecureSelectablePas
);
stage1_regime!(
    RealmEl2Stage1,
    RegimeOwner::El2,
    TranslationSpace::Realm,
    El2Permissions,
    RealmOrNonSecurePaPas
);
stage1_regime!(
    NonSecureEl2HostStage1,
    RegimeOwner::El2,
    TranslationSpace::NonSecure,
    El2And0Permissions,
    FixedNonSecurePas
);
stage1_regime!(
    SecureEl2HostStage1,
    RegimeOwner::El2,
    TranslationSpace::Secure,
    El2And0Permissions,
    SecureSelectablePas
);
stage1_regime!(
    RealmEl2HostStage1,
    RegimeOwner::El2,
    TranslationSpace::Realm,
    El2And0Permissions,
    RealmOrNonSecurePaPas
);
stage1_regime!(
    RootEl3Stage1,
    RegimeOwner::El3,
    TranslationSpace::Root,
    El3Permissions,
    RootExtendedPas
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonSecureEl2Stage2<P = Stage2Permissions>(PhantomData<fn() -> P>);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl2SecureIpaStage2<P = Stage2Permissions>(PhantomData<fn() -> P>);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl2NonSecureIpaStage2<P = Stage2Permissions>(PhantomData<fn() -> P>);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmEl2Stage2<P = Stage2Permissions>(PhantomData<fn() -> P>);

macro_rules! stage2_regime {
    ($name:ident, $context:ty, $space:expr, $ipa:expr) => {
        impl<P: Stage2PermissionModel> TranslationRegime for $name<P> {
            type WalkProfile = Stage2Walk;
            type PasModel = $context;
            const OWNER: RegimeOwner = RegimeOwner::El2;
            const SPACE: TranslationSpace = $space;
            const REQUIRED_FEATURES: FeatureRequirements =
                P::REQUIRED_FEATURES.union(<$context as PasModel>::REQUIRED_FEATURES);
        }
        impl<P: Stage2PermissionModel> Stage2Regime for $name<P> {
            type PermissionModel = P;
            const IPA_SPACE: IpaSpace = $ipa;
        }
    };
}

stage2_regime!(
    NonSecureEl2Stage2,
    NonSecureIpaContext,
    TranslationSpace::NonSecure,
    IpaSpace::NonSecure
);
stage2_regime!(
    SecureEl2SecureIpaStage2,
    SecureIpaContext,
    TranslationSpace::Secure,
    IpaSpace::Secure
);
stage2_regime!(
    SecureEl2NonSecureIpaStage2,
    SecureNonSecureIpaContext,
    TranslationSpace::Secure,
    IpaSpace::NonSecure
);
stage2_regime!(
    RealmEl2Stage2,
    RealmIpaContext,
    TranslationSpace::Realm,
    IpaSpace::Realm
);
