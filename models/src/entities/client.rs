use std::iter::Map;

#[derive(Debug)]
#[allow(dead_code)]
pub struct ClientModel {}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ClientProtocolMapper {
    mapper_id: String,
    realm_id: String,
    mapper: String,
    description: String,
    protocol: String,
    configs: Map<String, String>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ClientScope {}
