use crate::jose::jwe::{
    JweAlgorithmProvider, DirectAlgorithmProvider, 
    AesKeyWrapAlgorithmProvider, ECDKKeyEncryptionJweAlgorithmProvider, CekManagementAlgorithmEnum, 
    RsaKeyEncryptionJweAlgorithmProvider, Rsa15AlgorithmProvider
};

pub trait CekManagementProvider {
    fn algorithm_provider(&self) -> Box<dyn JweAlgorithmProvider>;
}


pub struct DirCekManagementProvider;

#[allow(dead_code)]
impl DirCekManagementProvider{
    fn id(&self) -> &'static str{
        "DIR"
    }
}

impl CekManagementProvider for DirCekManagementProvider{
    fn algorithm_provider(&self) -> Box<dyn JweAlgorithmProvider> {
        Box::new(DirectAlgorithmProvider{})
    }
}

pub struct A128KWCekManagementProvider;

#[allow(dead_code)]
impl A128KWCekManagementProvider{
    fn id(&self) -> &'static str{
        "A128KW"
    }
}

impl CekManagementProvider for A128KWCekManagementProvider{
    fn algorithm_provider(&self) -> Box<dyn JweAlgorithmProvider> {
        Box::new(AesKeyWrapAlgorithmProvider{})
    }
}

pub struct Rsa15CekManagementProvider;

#[allow(dead_code)]
impl Rsa15CekManagementProvider{
    fn id(&self) -> &'static str{
        "RSA1_5"
    }
}

impl CekManagementProvider for Rsa15CekManagementProvider{
    fn algorithm_provider(&self) -> Box<dyn JweAlgorithmProvider> {
        Box::new(Rsa15AlgorithmProvider{})
    }
}

pub struct RSAOAEPCekManagementProvider;

#[allow(dead_code)]
impl RSAOAEPCekManagementProvider{
    fn id(&self) -> &'static str{
        "RSA-OAEP"
    }
}

impl CekManagementProvider for RSAOAEPCekManagementProvider{
    fn algorithm_provider(&self) -> Box<dyn JweAlgorithmProvider> {
        Box::new(RsaKeyEncryptionJweAlgorithmProvider::new(CekManagementAlgorithmEnum::RsaOaep))
    }
}

pub struct RSAOAEP256CekManagementProvider;

#[allow(dead_code)]
impl RSAOAEP256CekManagementProvider{
    fn id(&self) -> &'static str{
        "RSA-OAEP-256"
    }
}

impl CekManagementProvider for RSAOAEP256CekManagementProvider{
    fn algorithm_provider(&self) -> Box<dyn JweAlgorithmProvider> {
        Box::new(RsaKeyEncryptionJweAlgorithmProvider::new(CekManagementAlgorithmEnum::RsaOaep256))
    }
}

pub struct ECDHESCekManagementProvider;
    
#[allow(dead_code)]
impl ECDHESCekManagementProvider{
    fn id(&self) -> &'static str{
        "ECDH-ES"
    }
}

impl CekManagementProvider for ECDHESCekManagementProvider{
    fn algorithm_provider(&self) -> Box<dyn JweAlgorithmProvider> {
        Box::new(ECDKKeyEncryptionJweAlgorithmProvider::new(CekManagementAlgorithmEnum::EcdhEs))
    }
}

pub struct ECDHESA128KWCekManagementProvider;

#[allow(dead_code)]
impl ECDHESA128KWCekManagementProvider{
    fn id(&self) -> &'static str{
        "ECDH-ES+A128KW"
    }
}

impl CekManagementProvider for ECDHESA128KWCekManagementProvider{
    fn algorithm_provider(&self) -> Box<dyn JweAlgorithmProvider> {
        Box::new(ECDKKeyEncryptionJweAlgorithmProvider::new(CekManagementAlgorithmEnum::EcdhEsA128kw))
    }
}

pub struct CekManagementProviderFactory;

impl CekManagementProviderFactory{
    pub fn encryption_provider(
        algorithm: &CekManagementAlgorithmEnum
    ) -> Box<dyn CekManagementProvider>{
        match &algorithm {
            CekManagementAlgorithmEnum::Dir => Box::new(DirCekManagementProvider),
            CekManagementAlgorithmEnum::Rsa1_5 => Box::new(Rsa15CekManagementProvider),
            CekManagementAlgorithmEnum::A128KW => Box::new(A128KWCekManagementProvider),
            CekManagementAlgorithmEnum::RsaOaep => Box::new(RSAOAEPCekManagementProvider),
            CekManagementAlgorithmEnum::RsaOaep256 => Box::new(RSAOAEP256CekManagementProvider),
            CekManagementAlgorithmEnum::EcdhEs => Box::new(ECDHESCekManagementProvider),
            CekManagementAlgorithmEnum::EcdhEsA128kw => Box::new(ECDHESA128KWCekManagementProvider),
        }
    }

    pub fn supported_algorithms() -> Vec<String>{
        vec![
            CekManagementAlgorithmEnum::Dir.to_string(),
            CekManagementAlgorithmEnum::Rsa1_5.to_string(),
            CekManagementAlgorithmEnum::A128KW.to_string(),
            CekManagementAlgorithmEnum::RsaOaep.to_string(),
            CekManagementAlgorithmEnum::RsaOaep256.to_string(),
            CekManagementAlgorithmEnum::EcdhEs.to_string(),
            CekManagementAlgorithmEnum::EcdhEsA128kw.to_string(),
        ]
    }
}