use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use base64_url::base64;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::Value;

use crate::jose::jose_error::JoseError;
use crate::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
use crate::jose::jwk::Jwk;
use crate::jose::jws::jws_algorithm::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::jose::util;
use crate::jose::util::der::{DerBuilder, DerReader, DerType};
use crate::jose::util::hash_algorithm::HashAlgorithm;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EcdsaJwsAlgorithm {
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// ECDSA using P-521 and SHA-512
    ES512,
    /// ECDSA using secp256k1 curve and SHA-256
    ES256k,
}

impl EcdsaJwsAlgorithm {
    pub fn generate_key_pair(&self) -> Result<EcKeyPair, JoseError> {
        let mut key_pair = EcKeyPair::generate(self.curve())?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    pub fn key_pair_from_der(&self, input: impl AsRef<[u8]>) -> Result<EcKeyPair, JoseError> {
        let mut key_pair = EcKeyPair::from_der(input, Some(self.curve()))?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    pub fn key_pair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EcKeyPair, JoseError> {
        let mut key_pair = EcKeyPair::from_pem(input.as_ref(), Some(self.curve()))?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<EcdsaJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_der(input.as_ref())?;
        Ok(EcdsaJwsSigner {
            algorithm: self.clone(),
            private_key: key_pair.into_private_key(),
            kid: None,
        })
    }

    pub fn signer_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EcdsaJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_pem(input.as_ref())?;
        Ok(EcdsaJwsSigner {
            algorithm: self.clone(),
            private_key: key_pair.into_private_key(),
            kid: None,
        })
    }

    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<EcdsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsSigner> {
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            if !jwk.is_for_key_operation("sign") {
                bail!("A parameter key_ops must contains sign.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
                None => {}
            }
            match jwk.curve() {
                Some(val) if val == self.curve().name() => {}
                Some(val) => bail!("A parameter crv must be {} but {}", self.name(), val),
                None => bail!("A parameter crv is required."),
            }

            let key_pair = EcKeyPair::from_jwk(jwk)?;
            let private_key = key_pair.into_private_key();
            let kid = jwk.kid().map(|val| val.to_string());

            Ok(EcdsaJwsSigner {
                algorithm: self.clone(),
                private_key,
                kid,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn verifier_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let spki_der = match EcKeyPair::detect_pkcs8(input.as_ref(), true) {
                Some(curve) if curve == self.curve() => input.as_ref(),
                Some(curve) => bail!("The curve is mismatched: {}", curve),
                None => {
                    bail!("The ECDSA public key must be wrapped by SubjectPublicKeyInfo format.")
                }
            };

            let public_key = PKey::public_key_from_der(spki_der)?;

            Ok(EcdsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                kid: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn verifier_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let (alg, data) = util::parse_pem(input.as_ref())?;

            let spki = match alg.as_str() {
                "PUBLIC KEY" => {
                    if let None = EcKeyPair::detect_pkcs8(&data, true) {
                        bail!("PEM contents is expected SubjectPublicKeyInfo wrapped key.");
                    }
                    &data
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let public_key = PKey::public_key_from_der(spki)?;

            Ok(EcdsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                kid: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<EcdsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let curve = self.curve();

            match jwk.key_type() {
                val if val == "EC" => {}
                val => bail!("A parameter kty must be EC: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            if !jwk.is_for_key_operation("verify") {
                bail!("A parameter key_ops must contains verify.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            match jwk.parameter("crv") {
                Some(Value::String(val)) if val == curve.name() => {}
                Some(Value::String(val)) => {
                    bail!("A parameter crv must be {} but {}", curve.name(), val)
                }
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            }
            let x = match jwk.parameter("x") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter x must be a string."),
                None => bail!("A parameter x is required."),
            };
            let y = match jwk.parameter("y") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter y must be a string."),
                None => bail!("A parameter y is required."),
            };

            let mut vec = Vec::with_capacity(1 + x.len() + y.len());
            vec.push(0x04);
            vec.extend_from_slice(&x);
            vec.extend_from_slice(&y);

            let pkcs8 = EcKeyPair::to_pkcs8(&vec, true, self.curve());
            let public_key = PKey::public_key_from_der(&pkcs8)?;
            let kid = jwk.kid().map(|val| val.to_string());

            Ok(EcdsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                kid: kid,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn curve(&self) -> EcCurve {
        match self {
            Self::ES256 => EcCurve::P256,
            Self::ES384 => EcCurve::P384,
            Self::ES512 => EcCurve::P521,
            Self::ES256k => EcCurve::Secp256k1,
        }
    }

    fn signature_len(&self) -> usize {
        match self {
            Self::ES256 | Self::ES256k => 64,
            Self::ES384 => 96,
            Self::ES512 => 132,
        }
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::ES256 => HashAlgorithm::Sha256,
            Self::ES384 => HashAlgorithm::Sha384,
            Self::ES512 => HashAlgorithm::Sha512,
            Self::ES256k => HashAlgorithm::Sha256,
        }
    }
}

impl JwsAlgorithm for EcdsaJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::ES256k => "ES256K",
        }
    }

    fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for EcdsaJwsAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for EcdsaJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct EcdsaJwsSigner {
    algorithm: EcdsaJwsAlgorithm,
    private_key: PKey<Private>,
    kid: Option<String>,
}

impl EcdsaJwsSigner {
    pub fn set_kid(&mut self, value: impl Into<String>) {
        self.kid = Some(value.into());
    }

    pub fn remove_kid(&mut self) {
        self.kid = None;
    }
}

impl JwsSigner for EcdsaJwsSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn signature_len(&self) -> usize {
        self.algorithm.signature_len()
    }

    fn kid(&self) -> Option<&str> {
        match &self.kid {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let md = self.algorithm.hash_algorithm().message_digest();

            let mut signer = Signer::new(md, &self.private_key)?;
            signer.update(message)?;
            let der_signature = signer.sign_to_vec()?;

            let signature_len = self.signature_len();
            let sep = signature_len / 2;

            let mut signature = Vec::with_capacity(signature_len);
            let mut reader = DerReader::from_bytes(&der_signature);
            match reader.next()? {
                Some(DerType::Sequence) => {}
                _ => unreachable!("A generated signature is invalid."),
            }
            match reader.next()? {
                Some(DerType::Integer) => {
                    signature.extend_from_slice(&reader.to_be_bytes(false, sep));
                }
                _ => unreachable!("A generated signature is invalid."),
            }
            match reader.next()? {
                Some(DerType::Integer) => {
                    signature.extend_from_slice(&reader.to_be_bytes(false, sep));
                }
                _ => unreachable!("A generated signature is invalid."),
            }

            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
}

impl Deref for EcdsaJwsSigner {
    type Target = dyn JwsSigner;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct EcdsaJwsVerifier {
    algorithm: EcdsaJwsAlgorithm,
    public_key: PKey<Public>,
    kid: Option<String>,
}

impl EcdsaJwsVerifier {
    pub fn set_kid(&mut self, value: impl Into<String>) {
        self.kid = Some(value.into());
    }

    pub fn remove_kid(&mut self) {
        self.kid = None;
    }
}

impl JwsVerifier for EcdsaJwsVerifier {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn kid(&self) -> Option<&str> {
        match &self.kid {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let signature_len = self.algorithm.signature_len();
            if signature.len() != signature_len {
                bail!(
                    "A signature size must be {}: {}",
                    signature_len,
                    signature.len()
                );
            }

            let mut der_builder = DerBuilder::new();
            der_builder.begin(DerType::Sequence);
            {
                let sep = signature_len / 2;

                let zeros = signature[..sep].iter().take_while(|b| **b == 0).count();
                der_builder.append_integer_from_be_slice(&signature[zeros..sep], true);
                let zeros = signature[sep..].iter().take_while(|b| **b == 0).count();
                der_builder.append_integer_from_be_slice(&signature[(sep + zeros)..], true);
            }
            der_builder.end();
            let der_signature = der_builder.build();

            let md = self.algorithm.hash_algorithm().message_digest();

            let mut verifier = Verifier::new(md, &self.public_key)?;
            verifier.update(message)?;
            if !verifier.verify(&der_signature)? {
                bail!("The signature does not match.");
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

impl Deref for EcdsaJwsVerifier {
    type Target = dyn JwsVerifier;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn sign_and_verify_ecdsa_generated_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256k,
        ] {
            let key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_der(&key_pair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&key_pair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_generated_raw() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256k,
        ] {
            let key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_der(&key_pair.to_raw_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&key_pair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_generated_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256k,
        ] {
            let key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_pem(&key_pair.to_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&key_pair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_generated_traditional_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256k,
        ] {
            let key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_pem(&key_pair.to_traditional_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&key_pair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_generated_jwk() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256k,
        ] {
            let key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_jwk(&key_pair.to_jwk_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&key_pair.to_jwk_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    /*#[test]
    fn sign_and_verify_ecdsa_jwt() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256k,
        ] {
            let private_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "jwk/EC_P-256_private.jwk",
                EcdsaJwsAlgorithm::ES384 => "jwk/EC_P-384_private.jwk",
                EcdsaJwsAlgorithm::ES512 => "jwk/EC_P-521_private.jwk",
                EcdsaJwsAlgorithm::ES256k => "jwk/EC_secp256k1_private.jwk",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "jwk/EC_P-256_public.jwk",
                EcdsaJwsAlgorithm::ES384 => "jwk/EC_P-384_public.jwk",
                EcdsaJwsAlgorithm::ES512 => "jwk/EC_P-521_public.jwk",
                EcdsaJwsAlgorithm::ES256k => "jwk/EC_secp256k1_public.jwk",
            })?;

            let signer = alg.signer_from_jwk(&Jwk::from_bytes(&private_key)?)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&Jwk::from_bytes(&public_key)?)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256k,
        ] {
            println!("{}", alg);

            let private_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "pem/EC_P-256_private.pem",
                EcdsaJwsAlgorithm::ES384 => "pem/EC_P-384_private.pem",
                EcdsaJwsAlgorithm::ES512 => "pem/EC_P-521_private.pem",
                EcdsaJwsAlgorithm::ES256k => "pem/EC_secp256k1_private.pem",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "pem/EC_P-256_public.pem",
                EcdsaJwsAlgorithm::ES384 => "pem/EC_P-384_public.pem",
                EcdsaJwsAlgorithm::ES512 => "pem/EC_P-521_public.pem",
                EcdsaJwsAlgorithm::ES256k => "pem/EC_secp256k1_public.pem",
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256k,
        ] {
            let private_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "der/EC_P-256_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES384 => "der/EC_P-384_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES512 => "der/EC_P-521_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES256k => "der/EC_secp256k1_pkcs8_private.der",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "der/EC_P-256_spki_public.der",
                EcdsaJwsAlgorithm::ES384 => "der/EC_P-384_spki_public.der",
                EcdsaJwsAlgorithm::ES512 => "der/EC_P-521_spki_public.der",
                EcdsaJwsAlgorithm::ES256k => "der/EC_secp256k1_spki_public.der",
            })?;

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }*/

    #[test]
    fn sign_and_verify_ecdsa_mismatch() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256k,
        ] {
            let signer_key_pair = alg.generate_key_pair()?;
            let verifier_key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_der(&signer_key_pair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&verifier_key_pair.to_der_public_key())?;
            verifier
                .verify(input, &signature)
                .expect_err("Unmatched signature did not fail");
        }

        Ok(())
    }

    fn load_file(path: &str) -> Result<Vec<u8>> {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("data");
        pb.push(path);

        let data = fs::read(&pb)?;
        Ok(data)
    }
}
