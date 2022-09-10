use crate::entities::realm::RealmModel;

pub struct OTPPolicy {
    pub otp_type: String,
    pub algorithm: String,
    pub initial_counter: i64,
    pub digits: i64,
    pub look_ahead_window: i64,
    pub period: i64,
}

impl OTPPolicy {
    pub fn from_realm(realm: &RealmModel) -> Self {
        todo!()
    }
}
