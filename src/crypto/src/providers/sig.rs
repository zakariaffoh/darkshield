use async_trait::async_trait;

use crate::{core::{keys::{KeyModel, MacSignature, SignatureAlgorithmEnum}, sig::RSASignature}};

use super::keys::RealmKeyProvider;

#[async_trait]
pub trait SignatureSignerContext{

    async fn kid(&self) -> Result<String, String>;

    async fn algorithm(&self) -> Result<String, String>;

    async fn hash_algorithm(&self) -> Result<String, String>;

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String>;
}

#[async_trait]
pub trait SignatureVerifierContext {

    async fn kid(&self) -> Result<String, String>;

    async fn algorithm(&self) -> Result<String, String>;

    async fn hash_algorithm(&self) -> Result<String, String>;

    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String>;
}


#[async_trait]
pub trait AsymmetricSignatureSignerContext: SignatureSignerContext{
    
    async fn kid(&self) -> Result<String, String>{
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok(k.kid().to_owned()),
            Err(err) => Err(err)
        }
    }

    async fn algorithm(&self) -> Result<String, String>{
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok(k.algorithm().to_owned()),
            Err(err) => Err(err)
        }
    }

    async fn hash_algorithm(&self) -> Result<String, String>{
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok( RSASignature::hash_algorithm(k.algorithm())),
            Err(err) => Err(err)
        }
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String>{
        let key = self.get_key().await;
        match key {
            Ok(k) => {  
                let algo =  key.algorithm();
                let mut verifier = RSASignature::new(algo);
                verifier.private_key(key.private_key());
                verifier.update(data);
                verifier.sign()
            }
            Err(err) => Err(err)
        }
    }
    async fn get_key(&self) -> Result<KeyModel, String>;
}


#[async_trait]
pub trait MacSignatureSignerContext: SignatureSignerContext{
    async fn kid(&self) -> &str{
        (self.get_key().await).kid()
    }

    async fn algorithm(&self) -> &str{
        (self.get_key().await).algorithm()
    }

    async fn hash_algorithm(&self) -> String{
        let algo = (self.get_key().await).algorithm();
        RSASignature::hash_algorithm(algo)
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String>{
       todo!()
    }

    async fn get_key(&self) -> &KeyModel;
}


#[async_trait]
pub trait AsymmetricSignatureVerifierContext: SignatureVerifierContext{
    async fn kid(&self) -> Result<String, String>{
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok(k.kid().to_owned()),
            Err(err) => Err(err)
        }
    }

    async fn algorithm(&self) -> Result<String, String>{
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok(k.algorithm().to_owned()),
            Err(err) => Err(err)
        }
    }

    async fn hash_algorithm(&self) -> Result<String, String>{
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok( RSASignature::hash_algorithm(k.algorithm())),
            Err(err) => Err(err)
        }
    }

    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String>{
        let key = self.get_key().await;
        match key {
            Ok(k) => {  
                let key = self.get_key().await;
                let algo =  key.algorithm();
                let mut verifier = RSASignature::new(algo);
                verifier.private_key(key.private_key());
                verifier.public_key(key.public_key());
                verifier.update(data);
                verifier.verify(signature)
            }
            Err(err) => Err(err)
        }
    }
    
    async fn get_key(&self) -> &KeyModel;
}

#[async_trait]
pub trait MacSignatureVerifierContext: SignatureVerifierContext{
    
    async fn kid(&self) -> &str{
        (self.get_key().await).kid()
    }

    async fn algorithm(&self) -> &str{
        (self.get_key().await).algorithm()
    }

    async fn hash_algorithm(&self) -> String{
        let algo = (self.get_key().await).algorithm();
        RSASignature::hash_algorithm(algo)
    }

    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String>{
        let key = self.get_key().await;
        let algorithm = key.algorithm();
        let signature_provider = MacSignature::new(algorithm);
        match signature_provider {
            Ok(provider) => {
                let result = provider.verify(data, &key.secret_key().encoded(), signature);
                return Ok(result)
            },
            Err(err) =>{
                Err(err)
            }  
        }
    }

    async fn get_key(&self) -> &KeyModel;
}

pub struct ServerAsymmetricSignatureSignerContext {
    realm_id: String,
    key_provider: dyn RealmKeyProvider,
    algorithm: SignatureAlgorithmEnum
}

impl ServerAsymmetricSignatureSignerContext{
    pub fn new(
        realm_id: &str,
        key_provider: dyn RealmKeyProvider,
        algorithm: SignatureAlgorithmEnum
    ) -> Self{
        Self { 
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm 
        }
    }
}

#[async_trait]
impl AsymmetricSignatureSignerContext for ServerAsymmetricSignatureSignerContext {
    async fn get_key(&self) -> Result<KeyModel, String>{
        self.key_provider.load_active_key(&self.realm_id, &crate::KeyUseEnum::SIG, &self.algorithm.to_string()).await
    }
}

impl SignatureSignerContext for ServerAsymmetricSignatureSignerContext{}

pub struct ServerECDSASignatureSignerContext{
    realm_id: String,
    key_provider: dyn RealmKeyProvider,
    algorithm: SignatureAlgorithmEnum
}

impl ServerECDSASignatureSignerContext{
    pub fn new(
        realm_id: &str,
        key_provider: dyn RealmKeyProvider,
        algorithm: SignatureAlgorithmEnum
    ) -> Self{
        Self { 
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm 
        }
    }
}

#[async_trait]
impl AsymmetricSignatureSignerContext for ServerECDSASignatureSignerContext {
    async fn get_key(&self) -> Result<KeyModel, String>{
        self.key_provider.load_active_key(&self.realm_id, &crate::KeyUseEnum::SIG, &self.algorithm.to_string()).await
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String>{
       todo!()
    }
}

impl SignatureSignerContext for ServerECDSASignatureSignerContext{}


pub struct ServerMacSignatureSignerContext{
    realm_id: String,
    key_provider: dyn RealmKeyProvider,
    algorithm: SignatureAlgorithmEnum
}

impl ServerMacSignatureSignerContext{
    pub fn new(
        realm_id: &str,
        key_provider: dyn RealmKeyProvider,
        algorithm: SignatureAlgorithmEnum
    ) -> Self{
        Self { 
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm 
        }
    }
}

#[async_trait]
impl MacSignatureSignerContext for ServerMacSignatureSignerContext {
    async fn get_key(&self) -> Result<KeyModel, String>{
        self.key_provider.load_active_key(&self.realm_id, &crate::KeyUseEnum::SIG, &self.algorithm.to_string()).await
    }
}

impl SignatureSignerContext for ServerMacSignatureSignerContext{}


pub struct ServerAsymmetricSignatureVerifierContext{
    realm_id: String,
    key_provider: dyn RealmKeyProvider,
    kid: String,
    algorithm: SignatureAlgorithmEnum
}

impl ServerAsymmetricSignatureVerifierContext{
    pub fn new(
        realm_id: &str,
        key_provider: dyn RealmKeyProvider,
        kid: &str,
        algorithm: SignatureAlgorithmEnum
    ) -> Self{
        Self { 
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            kid: kid.to_owned(),
            algorithm: algorithm 
        }
    }
}

#[async_trait]
impl AsymmetricSignatureVerifierContext for ServerAsymmetricSignatureVerifierContext {
    async fn get_key(&self) -> Result<KeyModel, String>{
        self.key_provider.load_active_key(&self.realm_id, &crate::KeyUseEnum::SIG, &self.algorithm.to_string()).await
    }
}

impl SignatureVerifierContext for ServerAsymmetricSignatureVerifierContext{}


pub struct ServerECDSASignatureVerifierContext{
    realm_id: String,
    key_provider: dyn RealmKeyProvider,
    kid: String,
    algorithm: SignatureAlgorithmEnum
}


impl ServerECDSASignatureVerifierContext{
    pub fn new(
        realm_id: &str,
        key_provider: dyn RealmKeyProvider,
        kid: &str,
        algorithm: SignatureAlgorithmEnum
    ) -> Self{
        Self { 
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            kid: kid.to_owned(),
            algorithm: algorithm 
        }
    }
}

#[async_trait]
impl AsymmetricSignatureVerifierContext for ServerECDSASignatureVerifierContext {
    async fn get_key(&self) -> Result<KeyModel, String>{
        self.key_provider.load_active_key(&self.realm_id, &crate::KeyUseEnum::SIG, &self.algorithm.to_string()).await
    }

    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String>{
        todo!()
    }
}

impl SignatureVerifierContext for ServerECDSASignatureVerifierContext{}


pub struct ServerMacSignatureVerifierContext{
    realm_id: String,
    key_provider: dyn RealmKeyProvider,
    kid: String,
    algorithm: SignatureAlgorithmEnum
}

impl ServerMacSignatureVerifierContext{
    pub fn new(
        realm_id: &str,
        key_provider: dyn RealmKeyProvider,
        kid: &str,
        algorithm: SignatureAlgorithmEnum
    ) -> Self{
        Self { 
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            kid: kid.to_owned(),
            algorithm: algorithm 
        }
    }
}

#[async_trait]
impl MacSignatureVerifierContext for ServerMacSignatureVerifierContext {
    async fn get_key(&self) -> Result<KeyModel, String>{
        self.key_provider.load_active_key(&self.realm_id, &crate::KeyUseEnum::SIG, &self.algorithm.to_string()).await
    }
}

impl SignatureVerifierContext for ServerMacSignatureVerifierContext{}


pub trait SignatureProvider{
    fn signer(&self) -> Box<dyn SignatureSignerContext>;

    fn verifier(&self, kid: &str)-> Box<dyn SignatureVerifierContext>; 

    fn is_asymmetric_algorithm(&self) -> bool;
}

pub struct AsymmetricSignatureProvider{
    realm_id: String,
    key_provider: Box<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum
}

impl AsymmetricSignatureProvider{
    pub fn new(
        realm_id: &str,
        key_provider: Box<dyn RealmKeyProvider>,
        algorithm: SignatureAlgorithmEnum
    ) -> Self{
        Self { 
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm 
        }
    }
}

impl SignatureProvider for AsymmetricSignatureProvider{
    fn signer(&self) -> Box<dyn SignatureSignerContext> {
        ServerAsymmetricSignatureSignerContext::new(
            &self.realm_id, &self.key_provider, &self.algorithm
        )
    }

    fn verifier(&self, kid: &str)-> Box<dyn SignatureVerifierContext> {
        ServerAsymmetricSignatureVerifierContext::new(
            &self.realm_id, &self.key_provider, kid, &self.algorithm
        )
    }

    fn is_asymmetric_algorithm(&self) -> bool {
        return true
    }
}


pub struct ECDSASignatureProvider{
    realm_id: String,
    key_provider: Box<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum
}

impl ECDSASignatureProvider{
    pub fn new(
        realm_id: &str,
        key_provider: Box<dyn RealmKeyProvider>,
        algorithm: SignatureAlgorithmEnum
    ) -> Self{
        Self { 
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm 
        }
    }
}

impl SignatureProvider for ECDSASignatureProvider{
    fn signer(&self) -> Box<dyn SignatureSignerContext> {
        ServerECDSASignatureSignerContext::new(
            &self.realm_id, &self.key_provider, &self.algorithm
        )
    }

    fn verifier(&self, kid: &str)-> Box<dyn SignatureVerifierContext> {
        ServerECDSASignatureVerifierContext::new(
            &self.realm_id, &self.key_provider, kid, &self.algorithm
        )
    }

    fn is_asymmetric_algorithm(&self) -> bool {
        return true
    }
}

pub struct MacSecretSignatureProvider{
    realm_id: String,
    key_provider: Box<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum
}

impl MacSecretSignatureProvider{
    pub fn new(
        realm_id: &str,
        key_provider: Box<dyn RealmKeyProvider>,
        algorithm: SignatureAlgorithmEnum
    ) -> Self{
        Self { 
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm 
        }
    }
}

impl SignatureProvider for MacSecretSignatureProvider{
    fn signer(&self) -> Box<dyn SignatureSignerContext> {
        ServerMacSignatureSignerContext::new(
            &self.realm_id, &self.key_provider, &self.algorithm
        )
    }

    fn verifier(&self, kid: &str)-> Box<dyn SignatureVerifierContext> {
        ServerMacSignatureVerifierContext::new(
            &self.realm_id, &self.key_provider, kid, &self.algorithm
        )
    }

    fn is_asymmetric_algorithm(&self) -> bool {
        return false
    }
}
 
pub struct SignatureProviderFactory;

impl SignatureProviderFactory {

    pub fn  supported_algorithms() -> Vec<String>{
        vec![
            SignatureAlgorithmEnum::HS256.to_string(),
            SignatureAlgorithmEnum::HS384.to_string(),
            SignatureAlgorithmEnum::HS512.to_string(),
            SignatureAlgorithmEnum::RS256.to_string(),
            SignatureAlgorithmEnum::RS384.to_string(),
            SignatureAlgorithmEnum::RS512.to_string(),
            SignatureAlgorithmEnum::ES256.to_string(),
            SignatureAlgorithmEnum::ES384.to_string(),
            SignatureAlgorithmEnum::ES512.to_string(),
            SignatureAlgorithmEnum::PS256.to_string(),
            SignatureAlgorithmEnum::PS384.to_string(),
            SignatureAlgorithmEnum::PS512.to_string(),
        ]
    }

    pub fn server_sinature_provider(
        realm_id:&str, realm_key_provider: &dyn RealmKeyProvider, algorithm: &SignatureAlgorithmEnum,
    ) -> Box<dyn SignatureProvider>{
        match &algorithm {
            SignatureAlgorithmEnum::RS256 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::RS256
            )),
            SignatureAlgorithmEnum::RS384 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::RS384
            )),
            SignatureAlgorithmEnum::RS512 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::RS512
            )),
            SignatureAlgorithmEnum::PS256 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::PS256
            )),
            SignatureAlgorithmEnum::PS384 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::PS384
            )),
            SignatureAlgorithmEnum::PS512 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::PS512
            )),
            SignatureAlgorithmEnum::HS256 => Box::new(MacSecretSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::HS256
            )),
            SignatureAlgorithmEnum::HS384 => Box::new(MacSecretSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::HS384
            )),
            SignatureAlgorithmEnum::HS512 => Box::new(MacSecretSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::HS512
            )),
            SignatureAlgorithmEnum::ES256 => Box::new(ECDSASignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::ES256
            )),
            SignatureAlgorithmEnum::ES384 => Box::new(ECDSASignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::ES384
            )),
            SignatureAlgorithmEnum::ES512 => Box::new(ECDSASignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::ES512
            )),
        }
    }


}


pub struct ClientSignatureVerifierProviderFactory;

impl ClientSignatureVerifierProviderFactory{
    pub fn  supported_algorithms() -> Vec<String>{
        vec![
            SignatureAlgorithmEnum::HS256.to_string(),
            SignatureAlgorithmEnum::HS384.to_string(),
            SignatureAlgorithmEnum::HS512.to_string(),
            SignatureAlgorithmEnum::RS256.to_string(),
            SignatureAlgorithmEnum::RS384.to_string(),
            SignatureAlgorithmEnum::RS512.to_string(),
            SignatureAlgorithmEnum::ES256.to_string(),
            SignatureAlgorithmEnum::ES384.to_string(),
            SignatureAlgorithmEnum::ES512.to_string(),
            SignatureAlgorithmEnum::PS256.to_string(),
            SignatureAlgorithmEnum::PS384.to_string(),
            SignatureAlgorithmEnum::PS512.to_string(),
        ]
    }

    pub fn client_sinature_provider(
        realm_id:&str, realm_key_provider: &dyn RealmKeyProvider, algorithm: &SignatureAlgorithmEnum,
    ) -> Box<dyn SignatureProvider>{
        match &algorithm {
            SignatureAlgorithmEnum::RS256 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::RS256
            )),
            SignatureAlgorithmEnum::RS384 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::RS384
            )),
            SignatureAlgorithmEnum::RS512 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::RS512
            )),
            SignatureAlgorithmEnum::PS256 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::PS256
            )),
            SignatureAlgorithmEnum::PS384 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::PS384
            )),
            SignatureAlgorithmEnum::PS512 => Box::new(AsymmetricSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::PS512
            )),
            SignatureAlgorithmEnum::HS256 => Box::new(MacSecretSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::HS256
            )),
            SignatureAlgorithmEnum::HS384 => Box::new(MacSecretSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::HS384
            )),
            SignatureAlgorithmEnum::HS512 => Box::new(MacSecretSignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::HS512
            )),
            SignatureAlgorithmEnum::ES256 => Box::new(ECDSASignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::ES256
            )),
            SignatureAlgorithmEnum::ES384 => Box::new(ECDSASignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::ES384
            )),
            SignatureAlgorithmEnum::ES512 => Box::new(ECDSASignatureProvider::new(
                realm_id, realm_key_provider, SignatureAlgorithmEnum::ES512
            )),
        }
    }


}