pub mod jwk;
pub mod jws;
pub mod jwe;

pub trait JoseHeader {
    fn algorithm(&self) -> &Option<String>;

    fn kid(&self) -> &Option<String>;
}

pub trait Jose {
    fn header(&self) -> &dyn JoseHeader;
}
