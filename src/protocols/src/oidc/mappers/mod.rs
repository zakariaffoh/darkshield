
pub struct ProtocolMapperPriorities{
    pub const PRIORITY_ROLE_NAMES_MAPPER: i64 = 10
    pub const PRIORITY_HARDCODED_ROLE_MAPPER: i64 = 20
    pub const PRIORITY_AUDIENCE_RESOLVE_MAPPER: i64 = 30
    pub const PRIORITY_ROLE_MAPPER: i64 = 40
}

pub struct OidcAttributesMapperConsts{

}

pub trait ProtocolMapper {

    fn id(&self) -> String;

    fn protocol(&self) -> String;
    
    fn priority(&self) -> i64;
}

pub trait UserInfoTokenMapper{

    fn transform_user_info(
        &self,
        context: &DarkshieldContext,
        token: &mut AccessToken,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &Box<ClientSessionContext>
    ) -> Result<AccessToken, String>;
}

pub trait OidcIDTokenMapper {
    fn transform_id_token(
        &self,
        context: &DarkshieldContext,
        token: &mut IdToken,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &Box<ClientSessionContext>
    ) -> Result<IdToken, String>;
}

pub trait OidcAccessTokenMapper {
    fn transform_id_token(
        &self,
        context: &DarkshieldContext,
        token: &mut AccessToken,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &Box<ClientSessionContext>
    ) -> Result<IdToken, String>;
}
        
pub trait OidcAccessTokenMapper {
    fn transform_id_token(
        &self,
        context: &DarkshieldContext,
        token: &mut AccessToken,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &Box<ClientSessionContext>
    ) -> Result<IdToken, String>;
}
    
pub trait OidcAccessTokenResponseMapper{
    fn transform_access_token_response(
        &self,
        context: &DarkshieldContext,
        access_token_response: &mut AccessTokenResponse,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &ClientSessionContext,
    ) -> Result<AccessTokenResponse, String>;
}

pub trait OidcTokenMapperBase: ProtocolMapper {
    fn protocol(&self) -> String{
        OidcLoginProtocolConsts::LOGIN_PROTOCOL
    }

    fn transform_user_info(
        &self,
        context: &DarkshieldContext,
        token: &mut AccessToken,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &Box<ClientSessionContext>
    ) -> Result<AccessToken, String>{
        if !OidcAttributeMapperHelper::include_in_user_info(&mapper){
            return Ok(token)
        }
        let response = self.set_access_token_claim(
            &context, &token, &mapper, &user_session, &client_session_ctx
        ).await;
        match response{
            Ok(_) => Ok(token),
            Err(err) => Err(err)
        }
    }

    fn transform_id_token(
        &self,
        context: &DarkshieldContext,
        token: &mut IdToken,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &Box<ClientSessionContext>
    ) -> Result<IdToken, String>{
        if !OidcAttributeMapperHelper::include_id_token(&mapper){
            return Ok(token)
        }
        let response = self.set_id_token_claim(
            &context, &token, &mapper, &user_session, &client_session_ctx
        ).await;
        match response{
            Ok(_) => Ok(token),
            Err(err) => Err(err)
        }
    }

    fn transform_access_token_response(
        &self,
        context: &DarkshieldContext,
        token: &mut AccessTokenResponse,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &ClientSessionContext,
    ) -> Result<AccessTokenResponse, String>{
        if !OidcAttributeMapperHelper::include_access_token_response(&mapper){
            return Ok(token)
        }
        let response = self.set_access_token_claim(
            &context, &token, &mapper, &user_session, &client_session_ctx
        ).await;
        match response{
            Ok(_) => Ok(token),
            Err(err) => Err(err)
        }
    }

    fn set_id_token_claim(
        &self,
        context: &DarkshieldContext,
        token: &mut IdToken,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &ClientSessionContext,
    ) -> Result<(), String>;


    fn set_access_token_claim(
        &self,
        context: &DarkshieldContext,
        token: &mut AccessTokenResponse,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &ClientSessionContext,
    ) -> Result<(), String>;

    fn set_access_token_claim(
        &self,
        context: &DarkshieldContext,
        token: &mut AccessToken,
        mapper: &ProtocolMapperModel,
        user_session: &UserSessionModel,
        client_session_ctx: &ClientSessionContext,
    ) -> Result<(), String>;

}

pub struct ProtocolMapperFactory;

impl ProtocolMapperFactory{
    fn create(mapper: &ProtocolMapperModel) -> Result<Box<dyn ProtocolMapper>, String>{
        match mapper.protocol_mapper_type{
            OidcAddressMapper::PROVIDER_ID => Ok(Bow::new(OidcAddressMapper::new())),
            UserFullNameMapper::PROVIDER_ID => Ok(Bow::new(UserFullNameMapper::new())),
            UserAttributeMapper::PROVIDER_ID => Ok(Bow::new(UserAttributeMapper::new())),
            UserPropertyMapper::PROVIDER_ID => Ok(Bow::new(UserPropertyMapper::new())),
            OidcAudienceMapper::PROVIDER_ID => Ok(Bow::new(OidcAudienceMapper::new())),
            AudienceResolveProtocolMapper::PROVIDER_ID => Ok(Bow::new(AudienceResolveProtocolMapper::new())),
            GroupMembershipMapper::PROVIDER_ID => Ok(Bow::new(GroupMembershipMapper::new())),
            HardCodedClaimMapper::PROVIDER_ID => Ok(Bow::new(HardCodedClaimMapper::new())),
            HardCodedRoleMapper::PROVIDER_ID => Ok(Bow::new(HardCodedRoleMapper::new())),
            RoleNameMapper::PROVIDER_ID => Ok(Bow::new(RoleNameMapper::new())),
            UserRealmRoleMappingMapper::PROVIDER_ID => Ok(Bow::new(UserRealmRoleMappingMapper::new())),
            UserSessionNoteMapper::PROVIDER_ID => Ok(Bow::new(UserSessionNoteMapper::new())),
            OidcWebOriginMapper::PROVIDER_ID => Ok(Bow::new(OidcWebOriginMapper::new())),
            ImpersonatorClaimMapper::PROVIDER_ID => Ok(Bow::new(ImpersonatorClaimMapper::new())),
            UserTenantMapper::PROVIDER_ID => Ok(Bow::new(UserTenantMapper::new())),
            _ => Err(format!("Protocol mapper: {} not supported", mapper)
        }
    }
}

pub struct ProtocolMapperHelper;

impl ProtocolMapperHelper{
    pub fn stored_protocol_mappers(
        client_session_ctx: &Box<ClientSessionContext>
    ) -> Result<HashMap<ProtocolMapperModel, Arc<dyn ProtocolMapper>>, String> {
        let protocols_mappers = client_session_ctx.protocol_mappers_stream().await;
        let mut mappers HashMap<ProtocolMapperModel, Arc<dyn ProtocolMapper>> = HashMap::new();
        for protocol in protocols_mappers.into_iter(){
            let protocol_mapper = ProtocolMapperFactory::create(&protocol);
            match &protocol_mapper{
                Ok(&mapper) => {
                    mappers. insert(protocol, Bow::clone(&protocol_mapper));
                },
                Err(err) => {
                    return Err(err);
                }
            }
        }  
        mappers
    }
}
