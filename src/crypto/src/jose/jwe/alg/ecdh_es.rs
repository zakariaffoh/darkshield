use std::borrow::Cow;
use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use openssl::aes::{self, AesKey};
use openssl::derive::Deriver;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Private, Public};

use crate::jose::jwk::alg::ec::EcCurve;
use crate::jose::jwk::alg::ecx::EcxCurve;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum EcdhEsKeyType {
    Ec(EcCurve),
    Ecx(EcxCurve),
}

impl EcdhEsKeyType {
    fn key_type(&self) -> &str {
        match self {
            Self::Ec(_) => "EC",
            Self::Ecx(_) => "OKP",
        }
    }

    fn curve_name(&self) -> &str {
        match self {
            Self::Ec(val) => val.name(),
            Self::Ecx(val) => val.name(),
        }
    }
}

impl Display for EcdhEsKeyType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.key_type())?;
        fmt.write_str("(")?;
        fmt.write_str(self.curve_name())?;
        fmt.write_str(")")?;
        Ok(())
    }
}
