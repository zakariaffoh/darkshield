use std::fmt::Debug;

pub enum TokenCategoryEnum {
    Id,
    Access,
    Internal,
    Admin,
    UserInfo,
    Logout,
    AuthorizationResponse,
}

pub trait Token: Debug + Send + Sync {
    fn category(&self) -> TokenCategoryEnum;
}
