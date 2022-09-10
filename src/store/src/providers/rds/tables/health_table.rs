use lazy_static::lazy_static;

lazy_static! {
    pub static ref HEALTH_CHECK_QUERY: &'static str = r#"SELECT 1 FROM REALMS"#;
}
