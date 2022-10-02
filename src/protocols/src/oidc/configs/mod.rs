
pub struct OidcAttributesMapperConsts{
    pub TOKEN_CLAIM_NAME: &'static str = "claim.name";
    pub INCLUDE_IN_USERINFO: &'static str  = "userinfo.token.claim";
    pub INCLUDE_IN_ACCESS_TOKEN: &'static str  = "access.token.claim";
    pub INCLUDE_IN_ACCESS_TOKEN_RESPONSE: &'static str  = "access.token_response.claim";
    pub INCLUDE_IN_ID_TOKEN: &'static str  = "id.token.claim";
    pub JSON_TYPE: &'static str  = "json_type.label";
    pub MULTIVALUED: &'static str  = "multivalued";
    pub USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID: &'static str  = "user_model.client_role_mapping.client_id";
    pub USER_MODEL_CLIENT_ROLE_MAPPING_ROLE_PREFIX: &'static str  = "user_model.client_role_mapping.role_prefix";
    pub USER_MODEL_REALM_ROLE_MAPPING_ROLE_PREFIX: &'static str  = "user_model.realm_role_mapping.role_prefix";
}

pub struct OidcAttributeMapperHelper;

impl OidcAttributeMapperHelper{

    pub fn include_id_token(mapper: &ProtocolMapperModel) -> bool{
        AttributeMapHelper::bool_value(
            &mapper.mapper_configs
            OidcAttributesMapperConsts::INCLUDE_IN_ID_TOKEN
        ).unwrap_or_default()
    }

    pub fn include_in_access_token(mapper: &ProtocolMapperModel) -> bool{
        AttributeMapHelper::bool_value(
            &mapper.mapper_configs
            OidcAttributesMapperConsts::INCLUDE_IN_ACCESS_TOKEN
        ).unwrap_or_default()
    }

    pub fn include_in_user_info(mapper: &ProtocolMapperModel) -> bool{
        let response = AttributeMapHelper::bool_value(
            &mapper.mapper_configs
            OidcAttributesMapperConsts::INCLUDE_IN_USERINFO
        ).unwrap_or_default();

        if not response{
            retun OidcAttributeMapperHelper::include_id_token(&mapper);
        }
        return response
    }

    pub fn include_access_token_response(mapper: &ProtocolMapperModel) -> bool{
        AttributeMapHelper::bool_value(
            &mapper.mapper_configs
            OidcAttributesMapperConsts::INCLUDE_IN_ACCESS_TOKEN_RESPONSE
        ).unwrap_or_default()
    }

    pub fn is_multi_valued(mapper: &ProtocolMapperModel) -> bool{
        AttributeMapHelper::bool_value(
            &mapper.mapper_configs,
            OidcAttributesMapperConsts::MULTIVALUED,
        )
    }

    pub fn  split_claim_path(protocol_claim: Option<str>) -> Vec<String>{
        todo!()
    }

    pub fn map_id_token_claim(
        token: &mut IdToken, 
        mapper: &ProtocolMapperModel, 
        attribute: ClaimValue
    ) -> Result<(), String> {
        OidcAttributeMapperHelper::map_claim(&mapper, &attribute_value, &token.others_claims)
    }

    pub fn map_access_token_response_claim(
        token: &mut AccessTokenResponse, 
        mapper: &ProtocolMapperModel, 
        attribute: ClaimValue
    ) -> Result<(), String> {
        OidcAttributeMapperHelper::map_claim(&mapper, &attribute_value, &token.others_claims)
    }   

    pub fn map_claim(
        mapper: &ProtocolMapperModel,
        attribute: Any,
        claims: HashMap<String, ClaimValue>,
    ) -> Result<(), String>{
        todo!()
    }
}