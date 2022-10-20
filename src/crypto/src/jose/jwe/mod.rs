pub mod enc;
pub mod jwe;

#[derive(Debug,PartialEq)]
pub enum CekManagementAlgorithmEnum{
    Rsa1_5,
    RsaOaep,
    RsaOaep256,
    Dir,
    A128KW,
    EcdhEs,
    EcdhEsA128kw,
}

impl TryFrom<&str> for CekManagementAlgorithmEnum {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().as_str() {
            "RSA1_5" => Ok(CekManagementAlgorithmEnum::Rsa1_5),
            "RSA_OAEP" => Ok(CekManagementAlgorithmEnum::RsaOaep),
            "RSA-OAEP" => Ok(CekManagementAlgorithmEnum::RsaOaep),
            "RSA_OAEP_256" => Ok(CekManagementAlgorithmEnum::RsaOaep256),
            "RSA-OAEP-256" => Ok(CekManagementAlgorithmEnum::RsaOaep256),
            "DIR" => Ok(CekManagementAlgorithmEnum::RsaOaep256),
            "A128KW" => Ok(CekManagementAlgorithmEnum::A128KW),
            "ECDH_ES" => Ok(CekManagementAlgorithmEnum::EcdhEs),
            "ECDH-ES" => Ok(CekManagementAlgorithmEnum::EcdhEs),
            "ECDH_ES_A128KW" => Ok(CekManagementAlgorithmEnum::EcdhEsA128kw),
            "ECDH-ES+A128KW" => Ok(CekManagementAlgorithmEnum::EcdhEsA128kw),
            _ => Err(format!("Value: {} is not supported", value)),
        }
    }
}

impl ToString for CekManagementAlgorithmEnum {
    fn to_string(&self) -> String {
        match &self {
            CekManagementAlgorithmEnum::Dir => "DIR".to_owned(),
            CekManagementAlgorithmEnum::Rsa1_5 => "RSA1_5".to_owned(),
            CekManagementAlgorithmEnum::A128KW => "A128KW".to_owned(),
            CekManagementAlgorithmEnum::RsaOaep => "RSA-OAEP".to_owned(),
            CekManagementAlgorithmEnum::RsaOaep256 => "RSA-OAEP-256".to_owned(),
            CekManagementAlgorithmEnum::EcdhEs => "ECDH-ES".to_owned(),
            CekManagementAlgorithmEnum::EcdhEsA128kw => "ECDH-ES+A128KW".to_owned(),
        }
    }
}


pub trait JweAlgorithmProvider{
    
}

pub struct DirectAlgorithmProvider;

impl JweAlgorithmProvider for DirectAlgorithmProvider{

}

pub struct AesKeyWrapAlgorithmProvider;

impl JweAlgorithmProvider for AesKeyWrapAlgorithmProvider{

}

pub struct Rsa15AlgorithmProvider;

impl JweAlgorithmProvider for Rsa15AlgorithmProvider{

}


pub struct RsaOaepCekAlgorithmProvider;

impl JweAlgorithmProvider for RsaOaepCekAlgorithmProvider{

}


pub struct RsaKeyEncryptionJweAlgorithmProvider{
    algorithm: CekManagementAlgorithmEnum
}

impl RsaKeyEncryptionJweAlgorithmProvider{
    pub fn new(algorithm: CekManagementAlgorithmEnum) -> Self{
        Self { algorithm }
    }
}

impl JweAlgorithmProvider for RsaKeyEncryptionJweAlgorithmProvider{
   
}


pub struct ECDKKeyEncryptionJweAlgorithmProvider{
    algorithm: CekManagementAlgorithmEnum
}

impl ECDKKeyEncryptionJweAlgorithmProvider{
    pub fn new(algorithm: CekManagementAlgorithmEnum) -> Self{
        Self { algorithm }
    }
}

impl JweAlgorithmProvider for ECDKKeyEncryptionJweAlgorithmProvider{
   
}

