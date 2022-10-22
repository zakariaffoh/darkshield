//! JSON Web Key (JWK) support.

pub mod alg;

mod jwk;
mod jwk_set;
mod key_info;
mod key_pair;

pub use crate::jose::jwk::jwk::Jwk;
pub use crate::jose::jwk::jwk_set::JwkSet;
pub use crate::jose::jwk::key_info::KeyAlg;
pub use crate::jose::jwk::key_info::KeyFormat;
pub use crate::jose::jwk::key_info::KeyInfo;
pub use crate::jose::jwk::key_pair::KeyPair;

pub use crate::jose::jwk::alg::ec::EcCurve::Secp256k1;
pub use crate::jose::jwk::alg::ec::EcCurve::P256 as P_256;
pub use crate::jose::jwk::alg::ec::EcCurve::P384 as P_384;
pub use crate::jose::jwk::alg::ec::EcCurve::P521 as P_521;

pub use crate::jose::jwk::alg::ed::EdCurve::Ed25519;
pub use crate::jose::jwk::alg::ed::EdCurve::Ed448;

pub use crate::jose::jwk::alg::ecx::EcxCurve::X25519;
pub use crate::jose::jwk::alg::ecx::EcxCurve::X448;
