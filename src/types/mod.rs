// src/types/mod.rs
pub mod claims;
pub mod vulnerability;
pub mod exploit;
pub mod output;

pub use claims::Claims;
pub use vulnerability::{Vulnerability, Severity, AttackExample};
pub use exploit::ExploitResult;