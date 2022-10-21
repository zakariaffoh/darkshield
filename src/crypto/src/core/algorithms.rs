#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AlgorithmsEnum {
    NONE,
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,

    // Content Encryption Algorithms
    A128CBC_HS256,
    A192CBC_HS384,
    A256CBC_HS512,
    A128GCM,
    A192GCM,
    A256GCM,

    // Pseudo algorithm for encryption
    A128CBC,
    A192CBC,
    A256CBC,

    // CEK Encryption Algorithms
    DIR,
    RSA1_5,
    RSA_OAEP,
    RSA_OAEP_256,
    A128KW,
    A192KW,
    A256KW,
    ECDH_ES,
    ECDH_ES_A128KW,
    ECDH_ES_A192KW,
    ECDH_ES_A256KW,
    A128GCMKW,
    A192GCMKW,
    A256GCMKW,
    PBES2_HS256_A128KW,
    PBES2_HS384_A192KW,
    PBES2_HS512_A256KW,
}

#[allow(dead_code)]
const HMAC: [&'static AlgorithmsEnum; 3] = [
    &AlgorithmsEnum::HS256,
    &AlgorithmsEnum::HS384,
    &AlgorithmsEnum::HS512,
];

#[allow(dead_code)]
const RSA_DS: [&'static AlgorithmsEnum; 3] = [
    &AlgorithmsEnum::RS256,
    &AlgorithmsEnum::RS384,
    &AlgorithmsEnum::RS512,
];

#[allow(dead_code)]
const RSA_KW: [&'static AlgorithmsEnum; 3] = [
    &AlgorithmsEnum::RSA1_5,
    &AlgorithmsEnum::RSA_OAEP,
    &AlgorithmsEnum::RSA_OAEP_256,
];

#[allow(dead_code)]
const RSA: [&'static AlgorithmsEnum; 6] = [
    &AlgorithmsEnum::RS256,
    &AlgorithmsEnum::RS384,
    &AlgorithmsEnum::RS512,
    &AlgorithmsEnum::RSA1_5,
    &AlgorithmsEnum::RSA_OAEP,
    &AlgorithmsEnum::RSA_OAEP_256,
];

#[allow(dead_code)]
const EC_DS: [&'static AlgorithmsEnum; 3] = [
    &AlgorithmsEnum::ES256,
    &AlgorithmsEnum::ES384,
    &AlgorithmsEnum::ES512,
];

#[allow(dead_code)]
const EC_KW: [&'static AlgorithmsEnum; 4] = [
    &AlgorithmsEnum::ECDH_ES,
    &AlgorithmsEnum::ECDH_ES_A128KW,
    &AlgorithmsEnum::ECDH_ES_A192KW,
    &AlgorithmsEnum::ECDH_ES_A256KW,
];

#[allow(dead_code)]
const EC: [&'static AlgorithmsEnum; 7] = [
    &AlgorithmsEnum::ES256,
    &AlgorithmsEnum::ES384,
    &AlgorithmsEnum::ES512,
    &AlgorithmsEnum::ECDH_ES,
    &AlgorithmsEnum::ECDH_ES_A128KW,
    &AlgorithmsEnum::ECDH_ES_A192KW,
    &AlgorithmsEnum::ECDH_ES_A256KW,
];

#[allow(dead_code)]
const AES_PSEUDO: [&'static AlgorithmsEnum; 6] = [
    &AlgorithmsEnum::A128CBC,
    &AlgorithmsEnum::A192CBC,
    &AlgorithmsEnum::A256CBC,
    &AlgorithmsEnum::A128GCM,
    &AlgorithmsEnum::A192GCM,
    &AlgorithmsEnum::A256GCM,
];

#[allow(dead_code)]
const AES_JWE_ENC: [&'static AlgorithmsEnum; 6] = [
    &AlgorithmsEnum::A128CBC_HS256,
    &AlgorithmsEnum::A192CBC_HS384,
    &AlgorithmsEnum::A256CBC_HS512,
    &AlgorithmsEnum::A128GCM,
    &AlgorithmsEnum::A192GCM,
    &AlgorithmsEnum::A256GCM,
];

#[allow(dead_code)]
const AES_ENC: [&'static AlgorithmsEnum; 9] = [
    &AlgorithmsEnum::A128CBC_HS256,
    &AlgorithmsEnum::A192CBC_HS384,
    &AlgorithmsEnum::A256CBC_HS512,
    &AlgorithmsEnum::A128GCM,
    &AlgorithmsEnum::A192GCM,
    &AlgorithmsEnum::A256GCM,
    &AlgorithmsEnum::A128CBC,
    &AlgorithmsEnum::A192CBC,
    &AlgorithmsEnum::A256CBC,
];

#[allow(dead_code)]
const AES_KW: [&'static AlgorithmsEnum; 3] = [
    &AlgorithmsEnum::A128KW,
    &AlgorithmsEnum::A192KW,
    &AlgorithmsEnum::A256KW,
];

#[allow(dead_code)]
const AES_GCM_KW: [&'static AlgorithmsEnum; 3] = [
    &AlgorithmsEnum::A128GCMKW,
    &AlgorithmsEnum::A192GCMKW,
    &AlgorithmsEnum::A256GCMKW,
];

#[allow(dead_code)]
pub const AES: [&'static AlgorithmsEnum; 12] = [
    &AlgorithmsEnum::A128CBC_HS256,
    &AlgorithmsEnum::A192CBC_HS384,
    &AlgorithmsEnum::A256CBC_HS512,
    &AlgorithmsEnum::A128GCM,
    &AlgorithmsEnum::A192GCM,
    &AlgorithmsEnum::A256GCM,
    &AlgorithmsEnum::A128CBC,
    &AlgorithmsEnum::A192CBC,
    &AlgorithmsEnum::A256CBC,
    &AlgorithmsEnum::A128KW,
    &AlgorithmsEnum::A192KW,
    &AlgorithmsEnum::A256KW,
];

#[allow(dead_code)]
const PBES2_KW: [&'static AlgorithmsEnum; 3] = [
    &AlgorithmsEnum::PBES2_HS256_A128KW,
    &AlgorithmsEnum::PBES2_HS384_A192KW,
    &AlgorithmsEnum::PBES2_HS512_A256KW,
];

#[allow(dead_code)]
const HMAC_AUTH_TAG: [&'static AlgorithmsEnum; 3] = [
    &AlgorithmsEnum::A128CBC_HS256,
    &AlgorithmsEnum::A192CBC_HS384,
    &AlgorithmsEnum::A256CBC_HS512,
];

#[allow(dead_code)]
const GCM: [&'static AlgorithmsEnum; 3] = [
    &AlgorithmsEnum::A128GCM,
    &AlgorithmsEnum::A192GCM,
    &AlgorithmsEnum::A256GCM,
];

impl TryFrom<&str> for AlgorithmsEnum {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().as_str() {
            "NONE" => Ok(AlgorithmsEnum::NONE),
            "HS256" => Ok(AlgorithmsEnum::HS256),
            "HS384" => Ok(AlgorithmsEnum::HS384),
            "HS512" => Ok(AlgorithmsEnum::HS512),
            "RS256" => Ok(AlgorithmsEnum::RS256),
            "RS384" => Ok(AlgorithmsEnum::RS384),
            "RS512" => Ok(AlgorithmsEnum::RS512),
            "ES256" => Ok(AlgorithmsEnum::ES256),
            "ES384" => Ok(AlgorithmsEnum::ES384),
            "ES512" => Ok(AlgorithmsEnum::ES512),
            "A128CBC_HS256" => Ok(AlgorithmsEnum::A128CBC_HS256),
            "A128CBC-HS256" => Ok(AlgorithmsEnum::A128CBC_HS256),
            "A192CBC_HS384" => Ok(AlgorithmsEnum::A192CBC_HS384),
            "A192CBC-HS384" => Ok(AlgorithmsEnum::A192CBC_HS384),
            "A256CBC_HS512" => Ok(AlgorithmsEnum::A256CBC_HS512),
            "A256CBC-HS512" => Ok(AlgorithmsEnum::A256CBC_HS512),
            "A128GCM" => Ok(AlgorithmsEnum::A128GCM),
            "A192GCM" => Ok(AlgorithmsEnum::A192GCM),
            "A256GCM" => Ok(AlgorithmsEnum::A256GCM),
            "A128CBC" => Ok(AlgorithmsEnum::A128CBC),
            "A192CBC" => Ok(AlgorithmsEnum::A192CBC),
            "A256CBC" => Ok(AlgorithmsEnum::A256CBC),

            "DIR" => Ok(AlgorithmsEnum::DIR),
            "dir" => Ok(AlgorithmsEnum::DIR),
            "RSA1_5" => Ok(AlgorithmsEnum::RSA1_5),
            "RSA_OAEP" => Ok(AlgorithmsEnum::RSA_OAEP),
            "RSA-OAEP" => Ok(AlgorithmsEnum::RSA_OAEP),
            "RSA_OAEP_256" => Ok(AlgorithmsEnum::RSA_OAEP_256),
            "RSA-OAEP-256" => Ok(AlgorithmsEnum::RSA_OAEP_256),

            "A128KW" => Ok(AlgorithmsEnum::A128KW),
            "A192KW" => Ok(AlgorithmsEnum::A192KW),
            "A256KW" => Ok(AlgorithmsEnum::A256KW),

            "ECDH_ES" => Ok(AlgorithmsEnum::ECDH_ES),
            "ECDH-ES" => Ok(AlgorithmsEnum::ECDH_ES),
            "ECDH_ES_A128KW" => Ok(AlgorithmsEnum::ECDH_ES_A128KW),
            "ECDH-ES+A128KW" => Ok(AlgorithmsEnum::ECDH_ES_A128KW),
            "ECDH_ES_A192KW" => Ok(AlgorithmsEnum::ECDH_ES_A192KW),
            "ECDH-ES+A192KW" => Ok(AlgorithmsEnum::ECDH_ES_A192KW),
            "ECDH_ES_A256KW" => Ok(AlgorithmsEnum::ECDH_ES_A256KW),
            "ECDH-ES+A256KW" => Ok(AlgorithmsEnum::ECDH_ES_A256KW),

            "A128GCMKW" => Ok(AlgorithmsEnum::A128GCMKW),
            "A192GCMKW" => Ok(AlgorithmsEnum::A192GCMKW),
            "A256GCMKW" => Ok(AlgorithmsEnum::A256GCMKW),

            "PBES2_HS256_A128KW" => Ok(AlgorithmsEnum::PBES2_HS256_A128KW),
            "PBES2-HS256+A128KW" => Ok(AlgorithmsEnum::PBES2_HS256_A128KW),
            "PBES2_HS384_A192KW" => Ok(AlgorithmsEnum::PBES2_HS384_A192KW),
            "PBES2-HS384+A192KW" => Ok(AlgorithmsEnum::PBES2_HS384_A192KW),
            "PBES2_HS512_A256KW" => Ok(AlgorithmsEnum::PBES2_HS512_A256KW),
            "PBES2-HS512+A256KW" => Ok(AlgorithmsEnum::PBES2_HS512_A256KW),
            _ => Err(format!("Value: {} is not supported", value)),
        }
    }
}

impl ToString for AlgorithmsEnum {
    fn to_string(&self) -> String {
        match &self {
            AlgorithmsEnum::NONE => "NONE".to_owned(),
            AlgorithmsEnum::HS256 => "HS256".to_owned(),
            AlgorithmsEnum::HS384 => "HS384".to_owned(),
            AlgorithmsEnum::HS512 => "HS512".to_owned(),
            AlgorithmsEnum::RS256 => "RS256".to_owned(),
            AlgorithmsEnum::RS384 => "RS384".to_owned(),
            AlgorithmsEnum::RS512 => "RS512".to_owned(),
            AlgorithmsEnum::ES256 => "ES256".to_owned(),
            AlgorithmsEnum::ES384 => "ES384".to_owned(),
            AlgorithmsEnum::ES512 => "ES512".to_owned(),
            AlgorithmsEnum::A128CBC_HS256 => "A128CBC-HS256".to_owned(),
            AlgorithmsEnum::A192CBC_HS384 => "A192CBC-HS384".to_owned(),
            AlgorithmsEnum::A256CBC_HS512 => "A256CBC-HS512".to_owned(),
            AlgorithmsEnum::A128GCM => "A128GCM".to_owned(),
            AlgorithmsEnum::A192GCM => "A192GCM".to_owned(),
            AlgorithmsEnum::A256GCM => "A256GCM".to_owned(),
            AlgorithmsEnum::A128CBC => "A128CBC".to_owned(),
            AlgorithmsEnum::A192CBC => "A192CBC".to_owned(),
            AlgorithmsEnum::A256CBC => "A256CBC".to_owned(),
            AlgorithmsEnum::DIR => "DIR".to_owned(),
            AlgorithmsEnum::RSA1_5 => "RSA1_5".to_owned(),
            AlgorithmsEnum::RSA_OAEP => "RSA-OAEP".to_owned(),
            AlgorithmsEnum::RSA_OAEP_256 => "RSA-OAEP-256".to_owned(),
            AlgorithmsEnum::A128KW => "A128KW".to_owned(),
            AlgorithmsEnum::A192KW => "A192KW".to_owned(),
            AlgorithmsEnum::A256KW => "A256KW".to_owned(),

            AlgorithmsEnum::ECDH_ES => "ECDH-ES".to_owned(),
            AlgorithmsEnum::ECDH_ES_A128KW => "ECDH-ES+A128KW".to_owned(),
            AlgorithmsEnum::ECDH_ES_A192KW => "ECDH-ES+A192KW".to_owned(),
            AlgorithmsEnum::ECDH_ES_A256KW => "ECDH-ES+A256KW".to_owned(),

            AlgorithmsEnum::A128GCMKW => "A128GCMKW".to_owned(),
            AlgorithmsEnum::A192GCMKW => "A192GCMKW".to_owned(),
            AlgorithmsEnum::A256GCMKW => "A256GCMKW".to_owned(),

            AlgorithmsEnum::PBES2_HS256_A128KW => "PBES2-HS256+A128KW".to_owned(),
            AlgorithmsEnum::PBES2_HS384_A192KW => "PBES2-HS384+A192KW".to_owned(),
            AlgorithmsEnum::PBES2_HS512_A256KW => "PBES2-HS512+A256KW".to_owned(),
        }
    }
}
