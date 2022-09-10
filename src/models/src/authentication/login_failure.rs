use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserLoginFailure {
    tenant: String,
    failure_id: String,
    user_id: String,
    realm_id: String,
    failed_login_not_before: i64,
    num_failures: i64,
    last_failure: i64,
    last_ip_failure: Option<String>,
}

impl UserLoginFailure {
    pub fn new(tenant: &str, failure_id: &str, user_id: &str, realm_id: &str) -> Self {
        Self {
            tenant: tenant.to_owned(),
            failure_id: failure_id.to_owned(),
            user_id: user_id.to_owned(),
            realm_id: realm_id.to_owned(),
            failed_login_not_before: 0,
            num_failures: 0,
            last_failure: 0,
            last_ip_failure: None,
        }
    }

    pub fn from_record(
        tenant: &str,
        failure_id: &str,
        user_id: &str,
        realm_id: &str,
        failed_login_not_before: i64,
        num_failures: i64,
        last_failure: i64,
        last_ip_failure: Option<String>,
    ) -> Self {
        Self {
            tenant: tenant.to_owned(),
            failure_id: failure_id.to_owned(),
            user_id: user_id.to_owned(),
            realm_id: realm_id.to_owned(),
            failed_login_not_before: failed_login_not_before,
            num_failures: num_failures,
            last_failure: last_failure,
            last_ip_failure: last_ip_failure,
        }
    }

    pub fn get_tenant(&self) -> &str {
        self.tenant.as_str()
    }

    pub fn get_failure_id(&self) -> &str {
        self.failure_id.as_str()
    }

    pub fn get_user_id(&self) -> &str {
        self.user_id.as_str()
    }

    pub fn get_realm_id(&self) -> &str {
        self.realm_id.as_str()
    }

    pub fn get_failed_login_not_before(&self) -> i64 {
        self.failed_login_not_before
    }

    pub fn get_num_failures(&self) -> i64 {
        self.num_failures
    }

    pub fn get_last_failure(&self) -> i64 {
        self.last_failure
    }

    pub fn get_last_ip_failure(&self) -> &Option<String> {
        &self.last_ip_failure
    }

    pub fn clear_failures(&mut self) {
        self.last_failure = 0;
        self.last_ip_failure = None;
        self.failed_login_not_before = 0;
        self.num_failures = 0
    }
}
