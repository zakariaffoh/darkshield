use models::entities::realm::RealmModel;

#[allow(dead_code)]
pub struct RealmService {}

impl<'d> RealmService {
    pub fn new() -> Self {
        Self {}
    }
    pub async fn create_realm(&self, realm: RealmModel) {}
}
