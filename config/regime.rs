use core::marker::PhantomData;

use super::stage2::Stage2Permissions;

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
pub struct NonSecureEl2Stage2<P = Stage2Permissions>(PhantomData<fn() -> P>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl2SecureIpaStage2<P = Stage2Permissions>(PhantomData<fn() -> P>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureEl2NonSecureIpaStage2<P = Stage2Permissions>(PhantomData<fn() -> P>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmEl2Stage2<P = Stage2Permissions>(PhantomData<fn() -> P>);
