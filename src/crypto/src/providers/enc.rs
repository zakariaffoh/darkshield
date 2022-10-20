use crate::jose::jwe::{
    enc::{
        JweEncryptionProvider, AesCbcHmacShaJweEncryptionProvider, AesGcmEncryptionProvider
    },
    jwe::ContentEncryptionAlgorithmEnum
};


pub trait ContentEncryptionProvider {
    fn encryption_provider(&self) -> Box<dyn JweEncryptionProvider>;
}

#[allow(dead_code)]
pub struct Aes128CbcHmacSha256ContentEncryptionProvider;

impl Aes128CbcHmacSha256ContentEncryptionProvider{
    pub fn provider(&self) -> String{
        "A128CBC-HS256".to_owned()
    }
}

impl  ContentEncryptionProvider for Aes128CbcHmacSha256ContentEncryptionProvider{
    fn encryption_provider(&self) -> Box<dyn JweEncryptionProvider> {
        Box::new(AesCbcHmacShaJweEncryptionProvider::new(&ContentEncryptionAlgorithmEnum::A128cbcHs256))
    }
}


#[allow(dead_code)]
pub struct Aes192CbcHmacSha384ContentEncryptionProvider;

impl Aes192CbcHmacSha384ContentEncryptionProvider{
    pub fn provider(&self) -> String{
        "A192CBC-HS384".to_owned()
    }
}

impl  ContentEncryptionProvider for Aes192CbcHmacSha384ContentEncryptionProvider{
    fn encryption_provider(&self) -> Box<dyn JweEncryptionProvider> {
        Box::new(AesCbcHmacShaJweEncryptionProvider::new(&ContentEncryptionAlgorithmEnum::A192cbcHs384))
    }
}

#[allow(dead_code)]
pub struct Aes256CbcHmacSha512ContentEncryptionProvider;

impl Aes256CbcHmacSha512ContentEncryptionProvider{
    pub fn provider(&self) -> String{
        "A256CBC-HS512".to_owned()
    }
}

impl  ContentEncryptionProvider for Aes256CbcHmacSha512ContentEncryptionProvider{
    fn encryption_provider(&self) -> Box<dyn JweEncryptionProvider> {
        Box::new(AesCbcHmacShaJweEncryptionProvider::new(&ContentEncryptionAlgorithmEnum::A256cbcHs512))
    }
}


#[allow(dead_code)]
pub struct Aes128GcmContentEncryptionProvider;

impl Aes128GcmContentEncryptionProvider{
    pub fn provider(&self) -> String{
        "A128GCM".to_owned()
    }
}

impl  ContentEncryptionProvider for Aes128GcmContentEncryptionProvider{
    fn encryption_provider(&self) -> Box<dyn JweEncryptionProvider> {
        Box::new(AesGcmEncryptionProvider::new(&ContentEncryptionAlgorithmEnum::A128GCM))
    }
}

#[allow(dead_code)]
pub struct Aes192GcmContentEncryptionProvider;

impl Aes192GcmContentEncryptionProvider{
    pub fn provider(&self) -> String{
        "A192GCM".to_owned()
    }
}

impl  ContentEncryptionProvider for Aes192GcmContentEncryptionProvider{
    fn encryption_provider(&self) -> Box<dyn JweEncryptionProvider> {
        Box::new(AesGcmEncryptionProvider::new(&ContentEncryptionAlgorithmEnum::A192GCM))
    }
}

#[allow(dead_code)]
pub struct Aes256GcmContentEncryptionProvider;

impl Aes256GcmContentEncryptionProvider{
    pub fn provider(&self) -> String{
        "A256GCM".to_owned()
    }
}

impl  ContentEncryptionProvider for Aes256GcmContentEncryptionProvider{
    fn encryption_provider(&self) -> Box<dyn JweEncryptionProvider> {
        Box::new(AesGcmEncryptionProvider::new(&ContentEncryptionAlgorithmEnum::A256GCM))
    }
}

pub struct ContentEncryptionProviderFactory;

impl ContentEncryptionProviderFactory{
    pub fn encryption_provider(
        algorithm: &ContentEncryptionAlgorithmEnum
    ) -> Box<dyn ContentEncryptionProvider>{
        match &algorithm {
            ContentEncryptionAlgorithmEnum::A128GCM => Box::new(Aes128GcmContentEncryptionProvider),
            ContentEncryptionAlgorithmEnum::A192GCM => Box::new(Aes192GcmContentEncryptionProvider),
            ContentEncryptionAlgorithmEnum::A256GCM => Box::new(Aes256GcmContentEncryptionProvider),
            ContentEncryptionAlgorithmEnum::A128cbcHs256 => Box::new(Aes128CbcHmacSha256ContentEncryptionProvider),
            ContentEncryptionAlgorithmEnum::A192cbcHs384 => Box::new(Aes192CbcHmacSha384ContentEncryptionProvider),
            ContentEncryptionAlgorithmEnum::A256cbcHs512 => Box::new(Aes256CbcHmacSha512ContentEncryptionProvider),
        }
    }

    pub fn supported_algorithms() -> Vec<String>{
        vec![
            ContentEncryptionAlgorithmEnum::A128GCM.to_string(),
            ContentEncryptionAlgorithmEnum::A192GCM.to_string(),
            ContentEncryptionAlgorithmEnum::A256GCM.to_string(),
            ContentEncryptionAlgorithmEnum::A128cbcHs256.to_string(),
            ContentEncryptionAlgorithmEnum::A192cbcHs384.to_string(),
            ContentEncryptionAlgorithmEnum::A256cbcHs512.to_string(),
        ]
    }
}