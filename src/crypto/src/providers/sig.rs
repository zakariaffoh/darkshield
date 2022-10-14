use async_trait::async_trait;

#[async_trait]
pub trait SignatureSignerContext {
    async fn kid(&self) -> Option<String>;

    async fn algorithm(&self) -> String;

    async fn sign(&self, encoding_jws_str: &str) -> Result<String, String>;
}
