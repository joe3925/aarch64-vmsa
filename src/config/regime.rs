use core::marker::PhantomData;

use super::stage2::StandardStage2PermissionModel;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonSecureEl1Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl1Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmEl1Stage1;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootEl3Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonSecureEl2Stage2<P = StandardStage2PermissionModel>(PhantomData<fn() -> P>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl2SecureIpaStage2<P = StandardStage2PermissionModel>(PhantomData<fn() -> P>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl2NonSecureIpaStage2<P = StandardStage2PermissionModel>(PhantomData<fn() -> P>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmEl2Stage2<P = StandardStage2PermissionModel>(PhantomData<fn() -> P>);

pub mod smmu_v2 {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct NonSecureStreamStage1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct NonSecurePrivilegedStreamStage1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SecureStreamStage1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SecurePrivilegedStreamStage1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct NonSecureIpaStage2;
}

pub mod smmu_v3 {
    use core::marker::PhantomData;

    use super::StandardStage2PermissionModel;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct NonSecureStreamStage1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct NonSecurePrivilegedStreamStage1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SecureStreamStage1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SecurePrivilegedStreamStage1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct RealmStreamStage1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct RealmPrivilegedStreamStage1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct NonSecureIpaStage2<P = StandardStage2PermissionModel>(PhantomData<fn() -> P>);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SecureIpaStage2<P = StandardStage2PermissionModel>(PhantomData<fn() -> P>);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SecureStreamNonSecureIpaStage2<P = StandardStage2PermissionModel>(
        PhantomData<fn() -> P>,
    );

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct RealmIpaStage2<P = StandardStage2PermissionModel>(PhantomData<fn() -> P>);
}
