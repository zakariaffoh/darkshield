pub trait Jwe{}

#[derive(Debug,PartialEq)]
pub enum ContentEncryptionAlgorithmEnum {
    A128GCM,
    A192GCM,
    A256GCM,
    A128cbcHs256,
    A192cbcHs384,
    A256cbcHs512,
}


impl TryFrom<&str> for ContentEncryptionAlgorithmEnum {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().as_str() {
            "A128GCM" => Ok(ContentEncryptionAlgorithmEnum::A128GCM),
            "A192GCM" => Ok(ContentEncryptionAlgorithmEnum::A192GCM),
            "A256GCM" => Ok(ContentEncryptionAlgorithmEnum::A192GCM),
            "A192CBC-HS384" => Ok(ContentEncryptionAlgorithmEnum::A192cbcHs384),
            "A192CBC_HS384" => Ok(ContentEncryptionAlgorithmEnum::A192cbcHs384),
            "A256CBC-HS512" => Ok(ContentEncryptionAlgorithmEnum::A256cbcHs512),
            "A256CBC_HS512" => Ok(ContentEncryptionAlgorithmEnum::A256cbcHs512),
            "A128CBC-HS256" => Ok(ContentEncryptionAlgorithmEnum::A128cbcHs256),
            "A128CBC_HS256" => Ok(ContentEncryptionAlgorithmEnum::A128cbcHs256),
            _ => Err(format!("Value: {} is not supported", value)),
        }
    }
}

impl ToString for ContentEncryptionAlgorithmEnum {
    fn to_string(&self) -> String {
        match &self {
            ContentEncryptionAlgorithmEnum::A128GCM => "A128GCM".to_owned(),
            ContentEncryptionAlgorithmEnum::A192GCM => "A192GCM".to_owned(),
            ContentEncryptionAlgorithmEnum::A256GCM => "A256GCM".to_owned(),
            ContentEncryptionAlgorithmEnum::A192cbcHs384 => "A192CBC-HS384".to_owned(),
            ContentEncryptionAlgorithmEnum::A256cbcHs512 => "A256CBC-HS512".to_owned(),
            ContentEncryptionAlgorithmEnum::A128cbcHs256 => "A128CBC-HS256".to_owned(),
        }
    }
}
