use std::sync::Arc;

use async_trait::async_trait;

use crate::core::{
    keys::{KeyModel, MacSignature, SignatureAlgorithmEnum},
    sig::RSASignature,
};

use super::keys::RealmKeyProvider;

#[async_trait]
pub trait SignatureSignerContext: Send + Sync {
    async fn kid(&self) -> Result<String, String> {
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok(k.kid().to_owned()),
            Err(err) => Err(err),
        }
    }

    async fn algorithm(&self) -> Result<String, String> {
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok(k.algorithm().to_owned()),
            Err(err) => Err(err),
        }
    }

    async fn hash_algorithm(&self) -> Result<String, String> {
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok(RSASignature::hash_algorithm(k.algorithm())),
            Err(err) => Err(err),
        }
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String>;

    async fn get_key(&self) -> Result<KeyModel, String>;
}

#[async_trait]
pub trait SignatureVerifierContext {
    async fn kid(&self) -> Result<String, String> {
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok(k.kid().to_owned()),
            Err(err) => Err(err),
        }
    }

    async fn algorithm(&self) -> Result<String, String> {
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok(k.algorithm().to_owned()),
            Err(err) => Err(err),
        }
    }

    async fn hash_algorithm(&self) -> Result<String, String> {
        let key = self.get_key().await;
        match key {
            Ok(k) => Ok(RSASignature::hash_algorithm(k.algorithm())),
            Err(err) => Err(err),
        }
    }

    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String>;

    async fn get_key(&self) -> Result<KeyModel, String>;
}

#[async_trait]
trait AsymmetricSignatureSignerContext: SignatureSignerContext {
    async fn sign_internal(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let provided_key = self.get_key().await;
        match provided_key {
            Ok(key) => {
                let algo = key.algorithm();
                let mut verifier = RSASignature::new(algo);
                verifier.private_key(key.private_key());
                verifier.update(data);
                verifier.sign()
            }
            Err(err) => Err(err),
        }
    }
}

#[async_trait]
trait MacSignatureSignerContext: SignatureSignerContext {
    async fn sign_internal(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let provider_key = self.get_key().await;
        match provider_key {
            Ok(key) => {
                let mac_sinature = MacSignature::new(key.algorithm());
                match mac_sinature {
                    Ok(signer) => signer.sign(key.secret_key().encoded(), data),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }
}

#[async_trait]
trait AsymmetricSignatureVerifierContext: SignatureVerifierContext {
    async fn verify_internal(&self, data: &[u8], signature: &[u8]) -> Result<bool, String> {
        let provided_key = self.get_key().await;
        match provided_key {
            Ok(key) => {
                let algo = key.algorithm();
                let mut verifier = RSASignature::new(algo);
                verifier.private_key(key.private_key());
                verifier.public_key(key.public_key());
                verifier.update(data);
                verifier.verify(signature)
            }
            Err(err) => Err(err),
        }
    }
}

#[async_trait]
trait MacSignatureVerifierContext: SignatureVerifierContext {
    async fn verify_internal(&self, data: &[u8], signature: &[u8]) -> Result<bool, String> {
        let provided_key = self.get_key().await;
        match provided_key {
            Ok(key) => {
                let provider = MacSignature::new(key.algorithm());
                match provider {
                    Ok(signer) => Ok(signer.verify(data, &key.secret_key().encoded(), signature)),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }
}

pub struct ServerAsymmetricSignatureSignerContext {
    realm_id: String,
    key_provider: Arc<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum,
}

impl ServerAsymmetricSignatureSignerContext {
    pub fn new(
        realm_id: &str,
        key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: &SignatureAlgorithmEnum,
    ) -> Self {
        Self {
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm.clone(),
        }
    }
}

#[async_trait]
impl AsymmetricSignatureSignerContext for ServerAsymmetricSignatureSignerContext {}

#[async_trait]
impl SignatureSignerContext for ServerAsymmetricSignatureSignerContext {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.sign_internal(data).await
    }

    async fn get_key(&self) -> Result<KeyModel, String> {
        self.key_provider
            .load_active_key(
                &self.realm_id,
                &crate::KeyUseEnum::SIG,
                &self.algorithm.to_string(),
            )
            .await
    }
}

pub struct ServerECDSASignatureSignerContext {
    realm_id: String,
    key_provider: Arc<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum,
}

impl ServerECDSASignatureSignerContext {
    pub fn new(
        realm_id: &str,
        key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: &SignatureAlgorithmEnum,
    ) -> Self {
        Self {
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm.clone(),
        }
    }
}

#[async_trait]
impl AsymmetricSignatureSignerContext for ServerECDSASignatureSignerContext {}

#[async_trait]
impl SignatureSignerContext for ServerECDSASignatureSignerContext {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        todo!()
    }

    async fn get_key(&self) -> Result<KeyModel, String> {
        self.key_provider
            .load_active_key(
                &self.realm_id,
                &crate::KeyUseEnum::SIG,
                &self.algorithm.to_string(),
            )
            .await
    }
}

pub struct ServerMacSignatureSignerContext {
    realm_id: String,
    key_provider: Arc<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum,
}

impl ServerMacSignatureSignerContext {
    pub fn new(
        realm_id: &str,
        key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: &SignatureAlgorithmEnum,
    ) -> Self {
        Self {
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm.clone(),
        }
    }
}

#[async_trait]
impl MacSignatureSignerContext for ServerMacSignatureSignerContext {}

#[async_trait]
impl SignatureSignerContext for ServerMacSignatureSignerContext {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.sign_internal(data).await
    }

    async fn get_key(&self) -> Result<KeyModel, String> {
        self.key_provider
            .load_active_key(
                &self.realm_id,
                &crate::KeyUseEnum::SIG,
                &self.algorithm.to_string(),
            )
            .await
    }
}

pub struct ServerAsymmetricSignatureVerifierContext {
    realm_id: String,
    key_provider: Arc<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum,
}

impl ServerAsymmetricSignatureVerifierContext {
    pub fn new(
        realm_id: &str,
        key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: &SignatureAlgorithmEnum,
    ) -> Self {
        Self {
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm.clone(),
        }
    }
}

impl AsymmetricSignatureVerifierContext for ServerAsymmetricSignatureVerifierContext {}

#[async_trait]
impl SignatureVerifierContext for ServerAsymmetricSignatureVerifierContext {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String> {
        self.verify_internal(data, signature).await
    }

    async fn get_key(&self) -> Result<KeyModel, String> {
        self.key_provider
            .load_active_key(
                &self.realm_id,
                &crate::KeyUseEnum::SIG,
                &self.algorithm.to_string(),
            )
            .await
    }
}

pub struct ServerECDSASignatureVerifierContext {
    realm_id: String,
    key_provider: Arc<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum,
}

impl ServerECDSASignatureVerifierContext {
    pub fn new(
        realm_id: &str,
        key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: &SignatureAlgorithmEnum,
    ) -> Self {
        Self {
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm.clone(),
        }
    }
}

impl AsymmetricSignatureVerifierContext for ServerECDSASignatureVerifierContext {}

#[async_trait]
impl SignatureVerifierContext for ServerECDSASignatureVerifierContext {
    async fn get_key(&self) -> Result<KeyModel, String> {
        self.key_provider
            .load_active_key(
                &self.realm_id,
                &crate::KeyUseEnum::SIG,
                &self.algorithm.to_string(),
            )
            .await
    }

    async fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, String> {
        todo!()
    }
}

pub struct ServerMacSignatureVerifierContext {
    realm_id: String,
    key_provider: Arc<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum,
}

impl ServerMacSignatureVerifierContext {
    pub fn new(
        realm_id: &str,
        key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: &SignatureAlgorithmEnum,
    ) -> Self {
        Self {
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm.clone(),
        }
    }
}

impl MacSignatureVerifierContext for ServerMacSignatureVerifierContext {}

#[async_trait]
impl SignatureVerifierContext for ServerMacSignatureVerifierContext {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String> {
        self.verify_internal(data, signature).await
    }
    async fn get_key(&self) -> Result<KeyModel, String> {
        self.key_provider
            .load_active_key(
                &self.realm_id,
                &crate::KeyUseEnum::SIG,
                &self.algorithm.to_string(),
            )
            .await
    }
}

pub trait SignatureProvider {
    fn signer(&self) -> Box<dyn SignatureSignerContext>;

    fn verifier(&self, kid: &str) -> Box<dyn SignatureVerifierContext>;

    fn is_asymmetric_algorithm(&self) -> bool;
}

pub struct AsymmetricSignatureProvider {
    realm_id: String,
    key_provider: Arc<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum,
}

impl AsymmetricSignatureProvider {
    pub fn new(
        realm_id: &str,
        key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: SignatureAlgorithmEnum,
    ) -> Self {
        Self {
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm,
        }
    }
}

impl SignatureProvider for AsymmetricSignatureProvider {
    fn signer(&self) -> Box<dyn SignatureSignerContext> {
        Box::new(ServerAsymmetricSignatureSignerContext::new(
            &self.realm_id,
            Arc::clone(&self.key_provider),
            &self.algorithm,
        ))
    }

    fn verifier(&self, _: &str) -> Box<dyn SignatureVerifierContext> {
        Box::new(ServerAsymmetricSignatureVerifierContext::new(
            &self.realm_id,
            Arc::clone(&self.key_provider),
            &self.algorithm,
        ))
    }

    fn is_asymmetric_algorithm(&self) -> bool {
        return true;
    }
}

pub struct ECDSASignatureProvider {
    realm_id: String,
    key_provider: Arc<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum,
}

impl ECDSASignatureProvider {
    pub fn new(
        realm_id: &str,
        key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: SignatureAlgorithmEnum,
    ) -> Self {
        Self {
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm,
        }
    }
}

impl SignatureProvider for ECDSASignatureProvider {
    fn signer(&self) -> Box<dyn SignatureSignerContext> {
        Box::new(ServerECDSASignatureSignerContext::new(
            &self.realm_id,
            Arc::clone(&self.key_provider),
            &self.algorithm,
        ))
    }

    fn verifier(&self, _: &str) -> Box<dyn SignatureVerifierContext> {
        Box::new(ServerECDSASignatureVerifierContext::new(
            &self.realm_id,
            Arc::clone(&self.key_provider),
            &self.algorithm,
        ))
    }

    fn is_asymmetric_algorithm(&self) -> bool {
        return true;
    }
}

pub struct MacSecretSignatureProvider {
    realm_id: String,
    key_provider: Arc<dyn RealmKeyProvider>,
    algorithm: SignatureAlgorithmEnum,
}

impl MacSecretSignatureProvider {
    pub fn new(
        realm_id: &str,
        key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: SignatureAlgorithmEnum,
    ) -> Self {
        Self {
            realm_id: realm_id.to_owned(),
            key_provider: key_provider,
            algorithm: algorithm,
        }
    }
}

impl SignatureProvider for MacSecretSignatureProvider {
    fn signer(&self) -> Box<dyn SignatureSignerContext> {
        Box::new(ServerMacSignatureSignerContext::new(
            &self.realm_id,
            Arc::clone(&self.key_provider),
            &self.algorithm,
        ))
    }

    fn verifier(&self, _: &str) -> Box<dyn SignatureVerifierContext> {
        Box::new(ServerMacSignatureVerifierContext::new(
            &self.realm_id,
            Arc::clone(&self.key_provider),
            &self.algorithm,
        ))
    }

    fn is_asymmetric_algorithm(&self) -> bool {
        return false;
    }
}

pub struct SignatureProviderFactory;

impl SignatureProviderFactory {
    pub fn supported_algorithms() -> Vec<String> {
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
        realm_id: &str,
        realm_key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: &SignatureAlgorithmEnum,
    ) -> Arc<dyn SignatureProvider> {
        match &algorithm {
            SignatureAlgorithmEnum::RS256 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::RS256,
            )),
            SignatureAlgorithmEnum::RS384 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::RS384,
            )),
            SignatureAlgorithmEnum::RS512 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::RS512,
            )),
            SignatureAlgorithmEnum::PS256 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::PS256,
            )),
            SignatureAlgorithmEnum::PS384 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::PS384,
            )),
            SignatureAlgorithmEnum::PS512 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::PS512,
            )),
            SignatureAlgorithmEnum::HS256 => Arc::new(MacSecretSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::HS256,
            )),
            SignatureAlgorithmEnum::HS384 => Arc::new(MacSecretSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::HS384,
            )),
            SignatureAlgorithmEnum::HS512 => Arc::new(MacSecretSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::HS512,
            )),
            SignatureAlgorithmEnum::ES256 => Arc::new(ECDSASignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::ES256,
            )),
            SignatureAlgorithmEnum::ES384 => Arc::new(ECDSASignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::ES384,
            )),
            SignatureAlgorithmEnum::ES512 => Arc::new(ECDSASignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::ES512,
            )),
        }
    }
}

pub struct ClientSignatureVerifierProviderFactory;

impl ClientSignatureVerifierProviderFactory {
    pub fn supported_algorithms() -> Vec<String> {
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
        realm_id: &str,
        realm_key_provider: Arc<dyn RealmKeyProvider>,
        algorithm: &SignatureAlgorithmEnum,
    ) -> Arc<dyn SignatureProvider> {
        match &algorithm {
            SignatureAlgorithmEnum::RS256 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::RS256,
            )),
            SignatureAlgorithmEnum::RS384 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::RS384,
            )),
            SignatureAlgorithmEnum::RS512 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::RS512,
            )),
            SignatureAlgorithmEnum::PS256 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::PS256,
            )),
            SignatureAlgorithmEnum::PS384 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::PS384,
            )),
            SignatureAlgorithmEnum::PS512 => Arc::new(AsymmetricSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::PS512,
            )),
            SignatureAlgorithmEnum::HS256 => Arc::new(MacSecretSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::HS256,
            )),
            SignatureAlgorithmEnum::HS384 => Arc::new(MacSecretSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::HS384,
            )),
            SignatureAlgorithmEnum::HS512 => Arc::new(MacSecretSignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::HS512,
            )),
            SignatureAlgorithmEnum::ES256 => Arc::new(ECDSASignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::ES256,
            )),
            SignatureAlgorithmEnum::ES384 => Arc::new(ECDSASignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::ES384,
            )),
            SignatureAlgorithmEnum::ES512 => Arc::new(ECDSASignatureProvider::new(
                realm_id,
                realm_key_provider,
                SignatureAlgorithmEnum::ES512,
            )),
        }
    }
}
