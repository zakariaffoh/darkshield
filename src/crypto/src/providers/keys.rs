use async_trait::async_trait;

use crate::{core::keys::KeyModel, KeyTypeEnum, KeyUseEnum};

pub trait RealmKeyGenerator {
    fn generate_keys(&self, key_model: &KeyModel) -> KeyModel;
}

pub struct RSARealmKeyGenerator;

impl RealmKeyGenerator for RSARealmKeyGenerator {
    fn generate_keys(&self, _key_model: &KeyModel) -> KeyModel {
        todo!()
    }
}

pub struct ECRealmKeyGenerator;

impl RealmKeyGenerator for ECRealmKeyGenerator {
    fn generate_keys(&self, _key_model: &KeyModel) -> KeyModel {
        todo!()
    }
}

pub struct SecretRealmKeyGenerator;

impl RealmKeyGenerator for SecretRealmKeyGenerator {
    fn generate_keys(&self, _key_model: &KeyModel) -> KeyModel {
        todo!()
    }
}

pub struct RealmKeyGeneratorFactory;

impl RealmKeyGeneratorFactory {
    pub fn new_generator(key_type: &KeyTypeEnum) -> Box<dyn RealmKeyGenerator> {
        match &key_type {
            KeyTypeEnum::RSA => Box::new(RSARealmKeyGenerator),
            KeyTypeEnum::EC => Box::new(ECRealmKeyGenerator),
            KeyTypeEnum::OTC => Box::new(SecretRealmKeyGenerator),
        }
    }
}

#[async_trait]
pub trait RealmKeyProvider: Sync + Send {
    async fn load_active_key(
        &self,
        realm_id: &str,
        key_use: &KeyUseEnum,
        algorithm: &str,
    ) -> Result<KeyModel, String>;
}
