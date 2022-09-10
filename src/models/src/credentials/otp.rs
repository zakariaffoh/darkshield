use crate::entities::realm::RealmModel;

pub struct OTPPolicy {
    otp_type: String,
    algorithm: String,
    initial_counter: i64,
    digits: i64,
    look_ahead_window: i64,
    period: i64,
}

impl OTPPolicy {
    pub fn new(
        otp_type: &str,
        algorithm: &str,
        initial_counter: i64,
        digits: i64,
        look_ahead_window: i64,
        period: i64,
    ) -> Self {
        Self {
            otp_type: otp_type.to_owned(),
            algorithm: algorithm.to_owned(),
            initial_counter: initial_counter.to_owned(),
            digits: digits,
            look_ahead_window: look_ahead_window,
            period: period,
        }
    }
    pub fn from_realm(realm: &RealmModel) -> Self {
        todo!()
    }

    pub fn otp_type(&self) -> &str {
        self.otp_type.as_str()
    }

    pub fn algorithm(&self) -> &str {
        self.algorithm.as_str()
    }

    pub fn initial_counter(&self) -> i64 {
        self.initial_counter
    }
    pub fn digits(&self) -> i64 {
        self.digits
    }
    pub fn look_ahead_window(&self) -> i64 {
        self.digits
    }
    pub fn period(&self) -> i64 {
        self.period
    }

    pub fn build_key_uri(&self) -> String {
        todo!()
    }
}

impl Default for OTPPolicy {
    fn default() -> Self {
        Self {
            otp_type: "TOTP".to_owned(),
            algorithm: "HmacSHA1".to_owned(),
            initial_counter: 0,
            digits: 6,
            look_ahead_window: 1,
            period: 30,
        }
    }
}
