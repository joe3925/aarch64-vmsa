#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod address;
pub mod arch;
pub mod attrs;
pub mod config;
pub mod descriptor;
pub mod mapper;
pub mod regime;
pub mod table;
pub mod translation;

pub use address::{addr, granule};
pub use arch::features;
pub use descriptor::format;

pub mod low_level {
    pub mod raw {
        pub use crate::attrs::raw::*;
    }
}
