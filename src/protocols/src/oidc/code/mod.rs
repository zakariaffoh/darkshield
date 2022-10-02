pub struct OidcAttributeMapperHelper;

impl OidcAttributeMapperHelper{
    pub fn include_id_token(mapper: &ProtocolMapperModel) -> bool{
        return AttributeHelper::bool_attribute_or_default(
            mapper.mapper_configs.get(
                OidcAttributesMapperConsts.INCLUDE_IN_ID_TOKEN, None
            ),
            False,
        )
    }
}