use super::jwe::{Jwe, ContentEncryptionAlgorithmEnum};

pub trait JweEncryptionProvider{
    fn encode_jwe(&self, jwe: &dyn Jwe) -> Vec<u8>;

    fn serialize_cek(&self) -> Vec<u8>;

    fn deserialize_cek(&self);

    fn verify_and_decode_jwe(&self, jwe: &dyn Jwe);
}
   

pub struct AesCbcHmacShaJweEncryptionProvider;

impl AesCbcHmacShaJweEncryptionProvider{
    pub fn new(algorithm: &ContentEncryptionAlgorithmEnum) -> Self{
        Self
    }
}

impl JweEncryptionProvider for AesCbcHmacShaJweEncryptionProvider{
    fn encode_jwe(&self, jwe: &dyn Jwe) -> Vec<u8> {
        todo!()
    }

    fn serialize_cek(&self) -> Vec<u8> {
        todo!()
    }

    fn deserialize_cek(&self) {
        todo!()
    }

    fn verify_and_decode_jwe(&self, jwe: &dyn Jwe) {
        todo!()
    }
}

pub struct AesGcmEncryptionProvider;

impl AesGcmEncryptionProvider{
    pub fn new(algorithm: &ContentEncryptionAlgorithmEnum)-> Self{
        Self
    }    
}

impl JweEncryptionProvider for AesGcmEncryptionProvider{
    fn encode_jwe(&self, jwe: &dyn Jwe) -> Vec<u8> {
        todo!()
    }

    fn serialize_cek(&self) -> Vec<u8> {
        todo!()
    }

    fn deserialize_cek(&self) {
        todo!()
    }

    fn verify_and_decode_jwe(&self, jwe: &dyn Jwe) {
        todo!()
    }
}