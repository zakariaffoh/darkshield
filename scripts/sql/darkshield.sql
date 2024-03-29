/*********************************************************************************************
*                                         SSLEnforcement Enum
**********************************************************************************************/
CREATE TYPE SslEnforcementEnum  AS ENUM ('NONE','ALL','EXTERNAL');

/*********************************************************************************************
*                                         PolicyEnforcementModeEnum Enum
**********************************************************************************************/
CREATE TYPE PolicyEnforcementModeEnum  AS ENUM ('Enforcing','Permissive','Disabled');

/*********************************************************************************************
*                                         DecisionStrategyEnum Enum
**********************************************************************************************/
CREATE TYPE DecisionStrategyEnum  AS ENUM ('Affirmative','Unanimous','Consensus');

/*********************************************************************************************
*                                     ProtocolEnum Enum
**********************************************************************************************/
CREATE TYPE ProtocolEnum  AS ENUM ('openid-connect','docker');

/*********************************************************************************************
*                                     AuthenticatorRequirement Enum
**********************************************************************************************/
CREATE TYPE AuthenticatorRequirementEnum  AS ENUM ('REQUIRED','CONDITIONAL','ALTERNATIVE', 'DISABLED');

/*********************************************************************************************
*                                         REALMS Table
**********************************************************************************************/

CREATE TABLE IF NOT EXISTS REALMS
(
    ID                                   serial                   PRIMARY KEY,
    TENANT                               varchar(50)              NOT NULL,
    REALM_ID                             varchar(250)             UNIQUE NOT NULL,
    NAME                                 TEXT                     NOT NULL,
    DISPLAY_NAME                         TEXT                     NOT NULL,
    ENABLED                              boolean,

    REGISTRATION_ALLOWED                 boolean,
    VERIFY_EMAIL                         boolean,
    RESET_PASSWORD_ALLOWED               boolean,
    LOGIN_WITH_EMAIL_ALLOWED             boolean,
    DUPLICATED_EMAIL_ALLOWED             boolean,
    REGISTER_EMAIL_AS_USERNAME           boolean,
    SSL_ENFORCEMENT                      SslEnforcementEnum,

    PASSWORD_POLICY                      JSON,
    EDIT_USER_NAME_ALLOWED               boolean,
    REVOKE_REFRESH_TOKEN                 boolean,
    REFRESH_TOKEN_MAX_REUSE              integer,

    ACCESS_TOKEN_LIFESPAN                integer,
    ACCESS_CODE_LIFESPAN                 integer,
    ACTION_TOKENS_LIFESPAN               integer,
    ACCESS_CODE_LIFESPAN_LOGIN           integer                DEFAULT 500,
    ACCESS_CODE_LIFESPAN_USER_ACTION     integer,

    NOT_BEFORE                           integer,
    REMEMBER_ME                          boolean,
    MASTER_ADMIN_CLIENT                  TEXT,
    EVENTS_ENABLED                       boolean,
    ADMIN_EVENTS_ENABLED                 boolean,
    ATTRIBUTES                           JSON,

    CREATED_BY                           varchar(250)            NOT NULL,
    CREATED_AT                           timestamptz             NOT NULL,
    UPDATED_BY                           varchar(250),
    UPDATED_AT                           timestamptz,
    VERSION                              integer                 DEFAULT 1   CHECK(version > 0)
);

DROP INDEX IF EXISTS REALMS_REALM_ID_IDX;
DROP INDEX IF EXISTS REALMS_NAME_IDX;
DROP INDEX IF EXISTS REALMS_DISPLAY_NAME_IDX;

CREATE INDEX REALMS_REALM_ID_IDX ON REALMS(REALM_ID);
CREATE INDEX REALMS_NAME_IDX ON REALMS(NAME);
CREATE INDEX REALMS_DISPLAY_NAME_IDX ON REALMS(DISPLAY_NAME);
CREATE UNIQUE INDEX REALMS_NAME_TENANT_UNIQUE_IDX ON REALMS(TENANT, NAME);


/********************************************************************************************
*                                           ROLES Table
*********************************************************************************************/

CREATE TABLE IF NOT EXISTS ROLES
(
    ID                                    serial                  PRIMARY KEY,
    TENANT                                varchar(50)             NOT NULL,
    ROLE_ID                               varchar(250)            UNIQUE NOT NULL,
    REALM_ID                              varchar(250)            NOT NULL,
    NAME                                  varchar(200)            NOT NULL,
    DISPLAY_NAME                          varchar(50)             NOT NULL,

    CLIENT_ROLE                           boolean,
    DESCRIPTION                           text,
    PERMISSIONS                           json,

    CREATED_BY                            varchar(250)            NOT NULL,
    CREATED_AT                            timestamptz             NOT NULL,
    UPDATED_BY                            varchar(250),
    UPDATED_AT                            timestamptz,
    VERSION                               integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_REALM_ROLES FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT UNIQUE_ROLES_REALM_ID_ROLE_ID UNIQUE (REALM_ID, ROLE_ID),
    CONSTRAINT UNIQUE_ROLES_REALM_ID_DISPLAY_NAME UNIQUE (REALM_ID, DISPLAY_NAME)
);

DROP INDEX IF EXISTS ROLES_ROLE_ID_IDX;
DROP INDEX IF EXISTS ROLES_REALM_ID_IDX;
DROP INDEX IF EXISTS ROLES_NAME_IDX;
DROP INDEX IF EXISTS ROLES_DISPLAY_NAME_IDX;
DROP INDEX IF EXISTS ROLES_CLIENT_ROLE_IDX;

CREATE INDEX ROLES_ROLE_ID_IDX ON ROLES(ROLE_ID);
CREATE INDEX ROLES_REALM_ID_IDX ON ROLES(REALM_ID);
CREATE INDEX ROLES_NAME_IDX ON ROLES(NAME);
CREATE INDEX ROLES_CLIENT_ROLE_IDX ON ROLES(CLIENT_ROLE);
CREATE INDEX ROLES_DISPLAY_NAME_IDX ON ROLES(DISPLAY_NAME);


/***********************************************************************************
*                                 GROUPS Table
************************************************************************************/
CREATE TABLE IF NOT EXISTS GROUPS
(
    ID                                    serial                  PRIMARY KEY,
    TENANT                                varchar(50)             NOT NULL,
    GROUP_ID                              varchar(250)            UNIQUE NOT NULL,
    REALM_ID                              varchar(250)            NOT NULL,
    NAME                                  varchar(200)            NOT NULL,

    DISPLAY_NAME                          TEXT                    NOT NULL,
    IS_DEFAULT                            boolean,
    DESCRIPTION                           TEXT                    NOT NULL,

    CREATED_BY                            varchar(250)            NOT NULL,
    CREATED_AT                            timestamptz             NOT NULL,
    UPDATED_BY                            varchar(250),
    UPDATED_AT                            timestamptz,
    VERSION                               integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_REALM_GROUPS FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT UNIQUE_GROUPS_REALM_ID_GROUP_ID UNIQUE (REALM_ID, GROUP_ID),
    CONSTRAINT UNIQUE_GROUPS_REALM_ID_DISPLAY_NAME UNIQUE (REALM_ID, DISPLAY_NAME)
);

DROP INDEX IF EXISTS GROUPS_GROUP_ID_IDX;
DROP INDEX IF EXISTS GROUPS_REALM_ID_IDX;
DROP INDEX IF EXISTS GROUPS_NAME_IDX;
DROP INDEX IF EXISTS GROUPS_DISPLAY_NAME_IDX;

CREATE INDEX GROUPS_GROUP_ID_IDX ON GROUPS(GROUP_ID);
CREATE INDEX GROUPS_REALM_ID_IDX ON GROUPS(REALM_ID);
CREATE INDEX GROUPS_NAME_IDX ON GROUPS(NAME);
CREATE INDEX GROUPS_DISPLAY_NAME_IDX ON GROUPS(DISPLAY_NAME);


/***********************************************************************************
*                           GROUPS_ROLES JOIN Table
************************************************************************************/

CREATE TABLE IF NOT EXISTS GROUPS_ROLES
(
    REALM_ID                              varchar(250)             NOT NULL,
    GROUP_ID                              varchar(250)             NOT NULL,
    ROLE_ID                               varchar(250)             NOT NULL,

    CONSTRAINT FK_GROUPS_ROLES_REALMS_GROUP_ID FOREIGN KEY(REALM_ID)
    REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,

    CONSTRAINT FK_GROUPS_ROLES_GROUPS_GROUP_ID FOREIGN KEY(GROUP_ID)
    REFERENCES GROUPS(GROUP_ID) ON DELETE CASCADE,

    CONSTRAINT FK_GROUPS_ROLES_ROLES_ROLE_ID FOREIGN KEY(ROLE_ID)
    REFERENCES ROLES(ROLE_ID) ON DELETE CASCADE,

    CONSTRAINT UNIQUE_GROUPS_ROLES_ROLE_ID_GROUP_ID UNIQUE (REALM_ID, GROUP_ID,ROLE_ID)
);

DROP INDEX IF EXISTS GROUPS_ROLES_REALM_ID_IDX;
DROP INDEX IF EXISTS GROUPS_ROLES_GROUP_ID_IDX;
DROP INDEX IF EXISTS GROUPS_ROLES_ROLE_ID_IDX;

CREATE INDEX GROUPS_ROLES_REALM_ID_IDX ON GROUPS_ROLES(REALM_ID);
CREATE INDEX GROUPS_ROLES_GROUP_ID_IDX ON GROUPS_ROLES(GROUP_ID);
CREATE INDEX GROUPS_ROLES_ROLE_ID_IDX ON GROUPS_ROLES(ROLE_ID);


/*********************************************************************************************
*                                    IDENTITIES_PROVIDERS Table
**********************************************************************************************/

CREATE TABLE IF NOT EXISTS IDENTITIES_PROVIDERS
(
    ID                                    serial                  PRIMARY KEY,
    TENANT                                varchar(50)             NOT NULL,
    INTERNAL_ID                           varchar(50)             UNIQUE NOT NULL,
    PROVIDER_ID                           varchar(250)            NOT NULL,
    REALM_ID                              varchar(250)            NOT NULL,
    NAME                                  TEXT                    NOT NULL,

    DISPLAY_NAME                          TEXT                    NOT NULL,
    DESCRIPTION                           TEXT                    NOT NULL,
    TRUST_EMAIL                           boolean,
    ENABLED                               boolean,
    CONFIGS                               JSON,

    CREATED_BY                            varchar(250)            NOT NULL,
    CREATED_AT                            timestamp               NOT NULL,
    UPDATED_BY                            varchar(250),
    UPDATED_AT                            timestamp,
    VERSION                               integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_IDP_REALMS_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT UNIQUE_IDP_REALM_ID_NAME UNIQUE (REALM_ID, NAME),
    CONSTRAINT UNIQUE_IDP_REALM_ID_DISPLAY_NAME UNIQUE (REALM_ID, DISPLAY_NAME)
);

DROP INDEX IF EXISTS IDENTITIES_PROVIDERS_PROVIDER_ID;
DROP INDEX IF EXISTS IDENTITIES_PROVIDERS_REALM_ID;
DROP INDEX IF EXISTS IDENTITIES_PROVIDERS_NAME;

CREATE INDEX IDENTITIES_PROVIDERS_PROVIDER_ID ON IDENTITIES_PROVIDERS(PROVIDER_ID);
CREATE INDEX IDENTITIES_PROVIDERS_REALM_ID ON IDENTITIES_PROVIDERS(REALM_ID);
CREATE INDEX IDENTITIES_PROVIDERS_NAME ON IDENTITIES_PROVIDERS(NAME);

/***************************************************************************************************
*                                         RESOURCES_SERVERS Table
****************************************************************************************************/

CREATE TABLE IF NOT EXISTS RESOURCES_SERVERS
(
    ID                                    serial                                PRIMARY KEY,
    TENANT                                varchar(50)                           NOT NULL,
    SERVER_ID                             varchar(250)                          UNIQUE NOT NULL,
    REALM_ID                              varchar(250)                          NOT NULL,
    NAME                                  TEXT                                  NOT NULL,
    DISPLAY_NAME                          TEXT                                  NOT NULL,
    DESCRIPTION                           TEXT                                  NOT NULL,

    POLICY_ENFORCEMENT_MODE               PolicyEnforcementModeEnum            NOT NULL,
    DECISION_STRATEGY                     DecisionStrategyEnum                 NOT NULL,
    SERVER_ICON_URI                       TEXT,
    REMOTE_RESOURCE_MANAGEMENT            bool,
    USER_MANAGED_ACCESS_ENABLED           bool,
    CONFIGS                               json,

    CREATED_BY                            varchar(250)                          NOT NULL,
    CREATED_AT                            timestamptz                           NOT NULL,
    UPDATED_BY                            varchar(250),
    UPDATED_AT                            timestamptz,
    VERSION                               integer                               DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_REALM_SCOPES FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT UNIQUE_RESOURCES_SERVERS_REALM_ID_NAME UNIQUE (REALM_ID, NAME),
    CONSTRAINT UNIQUE_RESOURCES_SERVERS_REALM_ID_DISPLAY_NAME UNIQUE (REALM_ID, DISPLAY_NAME)

);

DROP INDEX IF EXISTS RESOURCES_SERVERS_ID_IDX;
DROP INDEX IF EXISTS RESOURCES_REALM_ID_IDX;
DROP INDEX IF EXISTS RESOURCES_SERVERS_NAME_IDX;
DROP INDEX IF EXISTS RESOURCES_SERVERS_DISPLAY_NAME_IDX;

CREATE INDEX RESOURCES_SERVERS_ID_IDX ON RESOURCES_SERVERS(SERVER_ID);
CREATE INDEX RESOURCES_REALM_ID_IDX ON RESOURCES_SERVERS(REALM_ID);
CREATE INDEX RESOURCES_SERVERS_NAME_IDX ON RESOURCES_SERVERS(NAME);
CREATE INDEX RESOURCES_SERVERS_DISPLAY_NAME_IDX ON RESOURCES_SERVERS(DISPLAY_NAME);


/***********************************************************************************
*                                   SCOPES Table
************************************************************************************/

CREATE TABLE IF NOT EXISTS SCOPES
(
    ID                                    serial                  PRIMARY KEY,
    TENANT                                varchar(50)             NOT NULL,
    SCOPE_ID                              varchar(250)            UNIQUE NOT NULL,
    REALM_ID                              varchar(250)            NOT NULL,
    SERVER_ID                             varchar(250)            NOT NULL,

    NAME                                  varchar(200)            NOT NULL,
    DISPLAY_NAME                          varchar(200)            NOT NULL,
    DESCRIPTION                           varchar(200)            NOT NULL,

    CREATED_BY                            varchar(250)            NOT NULL,
    CREATED_AT                            timestamptz             NOT NULL,
    UPDATED_BY                            varchar(250),
    UPDATED_AT                            timestamptz,
    VERSION                               integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_REALM_SCOPES FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_RESOURCES_SERVER_SCOPES FOREIGN KEY(SERVER_ID) REFERENCES RESOURCES_SERVERS(SERVER_ID) ON DELETE CASCADE,
    CONSTRAINT UNIQUE_SCOPES_REALM_ID_SERVER_ID_NAME UNIQUE (REALM_ID, SERVER_ID, NAME),
    CONSTRAINT UNIQUE_SCOPES_REALM_ID_SERVER_ID_DISPLAY_NAME UNIQUE (REALM_ID, SERVER_ID, DISPLAY_NAME)
);

DROP INDEX IF EXISTS SCOPES_SCOPE_ID_IDX;
DROP INDEX IF EXISTS SCOPES_NAME_IDX;
DROP INDEX IF EXISTS SCOPES_DISPLAY_NAME_IDX;
DROP INDEX IF EXISTS SCOPES_SERVER_ID_IDX;

CREATE INDEX SCOPES_SCOPE_ID_IDX ON SCOPES(SCOPE_ID);
CREATE INDEX SCOPES_NAME_IDX ON SCOPES(NAME);
CREATE INDEX SCOPES_DISPLAY_NAME_IDX ON SCOPES(DISPLAY_NAME);
CREATE INDEX SCOPES_SERVER_ID_IDX ON SCOPES(SERVER_ID);


/***********************************************************************************
*                           RESOURCES Table
************************************************************************************/

CREATE TABLE IF NOT EXISTS RESOURCES
(
    ID                                    serial                  PRIMARY KEY,
    TENANT                                varchar(50)             NOT NULL,

    RESOURCE_ID                           varchar(250)            UNIQUE NOT NULL,
    SERVER_ID                             varchar(250)            NOT NULL,
    REALM_ID                              varchar(250)            NOT NULL,
    RESOURCE_OWNER                        varchar(150)            NOT NULL,

    NAME                                  varchar(150)            NOT NULL,
    DISPLAY_NAME                          varchar(150),
    DESCRIPTION                           TEXT                    NOT NULL,
    RESOURCE_URIS                         TEXT[],
    RESOURCE_TYPE                         varchar(150)            NOT NULL,
    USER_MANAGED_ACCESS_ENABLED           boolean,
    CONFIGS                               json,

    CREATED_BY                            varchar(250)            NOT NULL,
    CREATED_AT                            timestamptz             NOT NULL,
    UPDATED_BY                            varchar(250),
    UPDATED_AT                            timestamptz,
    VERSION                               integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_REALM_RESOURCES FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_RESOURCE_SERVERS FOREIGN KEY(SERVER_ID) REFERENCES RESOURCES_SERVERS(SERVER_ID) ON DELETE CASCADE,

    CONSTRAINT UNIQUE_RESOURCES_REALM_ID_NAME UNIQUE (REALM_ID, NAME),
    CONSTRAINT UNIQUE_RESOURCES_REALM_ID_DISPLAY_NAME UNIQUE (REALM_ID, DISPLAY_NAME)
);

DROP INDEX IF EXISTS RESOURCES_NAME_IDX;
DROP INDEX IF EXISTS RESOURCES_REALM_ID_IDX;
DROP INDEX IF EXISTS RESOURCES_RESOURCE_ID_IDX;
DROP INDEX IF EXISTS RESOURCES_RESOURCE_TYPE_IDX;
DROP INDEX IF EXISTS RESOURCES_SERVER_ID_IDX;

CREATE INDEX RESOURCES_NAME_IDX ON RESOURCES(NAME);
CREATE INDEX RESOURCES_REALM_ID_IDX ON RESOURCES(REALM_ID);
CREATE INDEX RESOURCES_RESOURCE_ID_IDX ON RESOURCES(RESOURCE_ID);
CREATE INDEX RESOURCES_SERVER_ID_IDX ON RESOURCES(SERVER_ID);
CREATE INDEX RESOURCES_RESOURCE_TYPE_IDX ON RESOURCES(RESOURCE_TYPE);


/***********************************************************************************
*                           RESOURCE_SCOPES Table
************************************************************************************/

CREATE TABLE IF NOT EXISTS RESOURCE_SCOPES
(
    REALM_ID                               varchar(250)             NOT NULL,
    SERVER_ID                              varchar(250)             NOT NULL,
    RESOURCE_ID                            varchar(250)             NOT NULL,
    SCOPE_ID                               varchar(250)             NOT NULL,

    CONSTRAINT FK_REALMS_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_RESOURCE_SERVER_ID FOREIGN KEY(SERVER_ID) REFERENCES RESOURCES_SERVERS(SERVER_ID) ON DELETE CASCADE,
    CONSTRAINT FK_RESOURCES_ID FOREIGN KEY(RESOURCE_ID) REFERENCES RESOURCES(RESOURCE_ID) ON DELETE CASCADE,
    CONSTRAINT FK_SCOPE_ID FOREIGN KEY(SCOPE_ID) REFERENCES SCOPES(SCOPE_ID) ON DELETE CASCADE,

    CONSTRAINT UNIQUE_SERVER_ID_RESOURCE_ID_SCOPE_ID UNIQUE (REALM_ID, SERVER_ID, RESOURCE_ID, SCOPE_ID)
);

DROP INDEX IF EXISTS RESOURCE_SCOPES_REALM_ID_IDX;
DROP INDEX IF EXISTS RESOURCE_SCOPES_SERVER_ID_IDX;
DROP INDEX IF EXISTS RESOURCE_SCOPES_RESOURCE_ID_IDX;
DROP INDEX IF EXISTS RESOURCE_SCOPES_SCOPE_ID_IDX;

CREATE INDEX RESOURCE_SCOPES_REALM_ID_IDX ON RESOURCE_SCOPES(REALM_ID);
CREATE INDEX RESOURCE_SCOPES_SERVER_ID_IDX ON RESOURCE_SCOPES(SERVER_ID);
CREATE INDEX RESOURCE_SCOPES_RESOURCE_ID_IDX ON RESOURCE_SCOPES(RESOURCE_ID);
CREATE INDEX RESOURCE_SCOPES_SCOPE_ID_IDX ON RESOURCE_SCOPES(SCOPE_ID);


/*********************************************************************************************************
*                                       PROTOCOLS_MAPPERS Table
**********************************************************************************************************/

CREATE TABLE IF NOT EXISTS PROTOCOLS_MAPPERS
(
    ID                                      serial                  PRIMARY KEY,
    TENANT                                  varchar(50)             NOT NULL,
    MAPPER_ID                               varchar(250)            UNIQUE NOT NULL,
    REALM_ID                                varchar(250)            NOT NULL,

    PROTOCOL                                ProtocolEnum            NOT NULL,
    NAME                                    varchar(250)            NOT NULL,
    MAPPER_TYPE                             varchar(250)            NOT NULL,

    CONFIGS                                 JSON,
    CREATED_BY                              varchar(250)            NOT NULL,
    CREATED_AT                              timestamptz             NOT NULL,
    UPDATED_BY                              varchar(250),
    UPDATED_AT                              timestamptz,
    VERSION                                 integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_PM_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES    REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT UNIQUE_PROTOCOLS_MAPPERS_REALM_ID_NAME UNIQUE (REALM_ID, NAME)

);

DROP INDEX IF EXISTS PROTOCOLS_MAPPERS_MAPPER_ID_IDX;
DROP INDEX IF EXISTS PROTOCOLS_MAPPERS_REALM_ID_IDX;
DROP INDEX IF EXISTS PROTOCOLS_MAPPERS_PROTOCOL_ID_IDX;
DROP INDEX IF EXISTS PROTOCOLS_MAPPERS_MAPPER_TYPE_IDX;

CREATE INDEX PROTOCOLS_MAPPERS_MAPPER_ID_IDX ON PROTOCOLS_MAPPERS(MAPPER_ID);
CREATE INDEX PROTOCOLS_MAPPERS_REALM_ID_IDX ON PROTOCOLS_MAPPERS(REALM_ID);
CREATE INDEX PROTOCOLS_MAPPERS_PROTOCOL_ID_IDX ON PROTOCOLS_MAPPERS(PROTOCOL);
CREATE INDEX PROTOCOLS_MAPPERS_MAPPER_TYPE_IDX ON PROTOCOLS_MAPPERS(MAPPER_TYPE);

/*********************************************************************************************************
*                                       CLIENTS Table
**********************************************************************************************************/

CREATE TABLE IF NOT EXISTS CLIENTS
(
    ID                                    serial                  PRIMARY KEY,
    TENANT                                varchar(50)             NOT NULL,
    CLIENT_ID                             varchar(250)            UNIQUE NOT NULL,
    REALM_ID                              varchar(250)            NOT NULL,
    NAME                                  TEXT                    NOT NULL,
    DISPLAY_NAME                          TEXT                    NOT NULL,

    DESCRIPTION                           TEXT,
    ENABLED                               boolean,
    SECRET                                TEXT,
    REGISTRATION_TOKEN                    TEXT,
    PUBLIC_CLIENT                         boolean,
    FULL_SCOPE_ALLOWED                    boolean,

    PROTOCOL                              ProtocolEnum,
    ROOT_URL                              TEXT,
    WEB_ORIGINS                           TEXT[],
    REDIRECT_URIS                         TEXT[],

    CONSENT_REQUIRED                      boolean,
    AUTHORIZATION_CODE_FLOW_ENABLED       boolean,
    IMPLICIT_FLOW_ENABLED                 boolean,
    DIRECT_ACCESS_GRANTS_ENABLED          boolean,
    STANDARD_FLOW_ENABLED                 boolean,
    IS_SURROGATE_AUTH_REQUIRED            boolean,

    NOT_BEFORE                            integer,
    BEARER_ONLY                           boolean,
    FRONT_CHANNEL_LOGOUT                  boolean,

    CONFIGS                               json,
    CLIENT_AUTHENTICATOR_TYPE             text,
    SERVICE_ACCOUNT_ENABLED               boolean,
    AUTH_FLOW_BINDING_OVERRIDES           json,

    CREATED_BY                            varchar(250)            NOT NULL,
    CREATED_AT                            timestamptz             NOT NULL,
    UPDATED_BY                            varchar(250),
    UPDATED_AT                            timestamptz,
    VERSION                               integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_CLIENT_REALMS_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT UNIQUE_CLIENTS_REALM_ID_NAME UNIQUE (REALM_ID, NAME),
    CONSTRAINT UNIQUE_CLIENTS_REALM_ID_DISPLAY_NAME UNIQUE (REALM_ID, DISPLAY_NAME)
);

DROP INDEX IF EXISTS CLIENTS_CLIENT_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_REALM_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_NAME_IDX;
DROP INDEX IF EXISTS CLIENTS_DISPLAY_NAME_IDX;
DROP INDEX IF EXISTS CLIENTS_SVC_ENABLED_IDX;

CREATE INDEX CLIENTS_CLIENT_ID_IDX ON CLIENTS(CLIENT_ID);
CREATE INDEX CLIENTS_REALM_ID_IDX ON CLIENTS(REALM_ID);
CREATE INDEX CLIENTS_NAME_IDX ON CLIENTS(NAME);
CREATE INDEX CLIENTS_DISPLAY_NAME_IDX ON CLIENTS(DISPLAY_NAME);
CREATE INDEX CLIENTS_SVC_ENABLED_IDX ON CLIENTS(SERVICE_ACCOUNT_ENABLED);

/*********************************************************************************************************
*                                             CLIENTS_ROLES Table
**********************************************************************************************************/

CREATE TABLE IF NOT EXISTS CLIENTS_ROLES
(
    REALM_ID                                   varchar(250)             NOT NULL,
    CLIENT_ID                                  varchar(250)             NOT NULL,
    ROLE_ID                                    varchar(250)             NOT NULL,

    CONSTRAINT FK_REALMS_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_CLIENT_ID FOREIGN KEY(CLIENT_ID) REFERENCES CLIENTS(CLIENT_ID) ON DELETE CASCADE,
    CONSTRAINT FK_ROLE_ID FOREIGN KEY(ROLE_ID) REFERENCES ROLES(ROLE_ID) ON DELETE CASCADE,


    CONSTRAINT UNIQUE_CLIENTS_ROLES_REALM_ID_CLIENT_ID_ROLE_ID UNIQUE (REALM_ID, CLIENT_ID, ROLE_ID)
);

DROP INDEX IF EXISTS CLIENTS_ROLES_REALM_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_ROLES_CLIENT_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_ROLES_ROLE_ID_IDX;

CREATE INDEX CLIENTS_ROLES_REALM_ID_IDX ON CLIENTS_ROLES(REALM_ID);
CREATE INDEX CLIENTS_ROLES_CLIENT_ID_IDX ON CLIENTS_ROLES(CLIENT_ID);
CREATE INDEX CLIENTS_ROLES_ROLE_ID_IDX ON CLIENTS_ROLES(ROLE_ID);



/*****************************************************************************************************
*                                            CLIENTS_SCOPES Table
******************************************************************************************************/

CREATE TABLE IF NOT EXISTS CLIENTS_SCOPES
(
    ID                                      serial                  PRIMARY KEY,
    TENANT                                  varchar(50)             NOT NULL,
    CLIENT_SCOPE_ID                         varchar(250)            UNIQUE NOT NULL,
    REALM_ID                                varchar(250)            NOT NULL,
    NAME                                    TEXT                    NOT NULL,
    DESCRIPTION                             TEXT,
    PROTOCOL                                ProtocolEnum,
    DEFAULT_SCOPE                           boolean,
    CONFIGS                                 json,

    CREATED_BY                              varchar(250)            NOT NULL,
    CREATED_AT                              timestamptz             NOT NULL,
    UPDATED_BY                              varchar(250),
    UPDATED_AT                              timestamptz,
    VERSION                                 integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_CLIENTS_SCOPES_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES  REALMS(REALM_ID) ON DELETE CASCADE
);

DROP INDEX IF EXISTS CLIENTS_SCOPES_CLIENT_SCOPE_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_SCOPES_CLIENT_REALM_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_SCOPES_CLIENT_PROTOCOL_IDX;

CREATE INDEX CLIENTS_SCOPES_CLIENT_SCOPE_ID_IDX ON CLIENTS_SCOPES(CLIENT_SCOPE_ID);
CREATE INDEX CLIENTS_SCOPES_CLIENT_REALM_ID_IDX ON CLIENTS_SCOPES(REALM_ID);
CREATE INDEX CLIENTS_SCOPES_CLIENT_PROTOCOL_IDX ON CLIENTS_SCOPES(PROTOCOL);

/*********************************************************************************************************
*                                             CLIENTS_CLIENTS_SCOPES Table
**********************************************************************************************************/

CREATE TABLE IF NOT EXISTS CLIENTS_CLIENTS_SCOPES
(
    REALM_ID                                   varchar(250)             NOT NULL,
    CLIENT_ID                                  varchar(250)             NOT NULL,
    CLIENT_SCOPE_ID                            varchar(250)             NOT NULL,

    CONSTRAINT FK_REALMS_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_CLIENT_ID FOREIGN KEY(CLIENT_ID) REFERENCES CLIENTS(CLIENT_ID) ON DELETE CASCADE,
    CONSTRAINT FK_CLIENT_SCOPE_ID FOREIGN KEY(CLIENT_SCOPE_ID) REFERENCES CLIENTS_SCOPES(CLIENT_SCOPE_ID) ON DELETE CASCADE,


    CONSTRAINT UNIQUE_CLIENTS_CLIENTS_SCOPES_REALM_ID_CLIENT_ID_CLIENT_SCOPE_ID UNIQUE (REALM_ID, CLIENT_ID, CLIENT_SCOPE_ID)
);

DROP INDEX IF EXISTS CLIENTS_CLIENTS_SCOPES_REALM_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_CLIENTS_SCOPES_CLIENT_SCOPE_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_CLIENTS_SCOPES_ROLE_ID_IDX;

CREATE INDEX CLIENTS_CLIENTS_SCOPES_REALM_ID_IDX ON CLIENTS_CLIENTS_SCOPES(REALM_ID);
CREATE INDEX CLIENTS_CLIENTS_SCOPES_CLIENT_ID_IDX ON CLIENTS_CLIENTS_SCOPES(CLIENT_ID);
CREATE INDEX CLIENTS_CLIENTS_SCOPES_CLIENT_SCOPE_ID_IDX ON CLIENTS_CLIENTS_SCOPES(CLIENT_SCOPE_ID);

/*********************************************************************************************************
*                                             CLIENTS_PROTOCOLS_MAPPERS Table
**********************************************************************************************************/

CREATE TABLE IF NOT EXISTS CLIENTS_PROTOCOLS_MAPPERS
(
    REALM_ID                                   varchar(250)             NOT NULL,
    CLIENT_ID                                  varchar(250)             NOT NULL,
    MAPPER_ID                                  varchar(250)             NOT NULL,

    CONSTRAINT FK_REALMS_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_CLIENT_ID FOREIGN KEY(CLIENT_ID) REFERENCES CLIENTS(CLIENT_ID) ON DELETE CASCADE,
    CONSTRAINT FK_MAPPER_ID FOREIGN KEY(MAPPER_ID) REFERENCES PROTOCOLS_MAPPERS(MAPPER_ID) ON DELETE CASCADE,


    CONSTRAINT UNIQUE_CLIENTS_PROTOCOLS_MAPPERS_REALM_ID_CLIENT_ID_MAPPER_ID UNIQUE (REALM_ID, CLIENT_ID, MAPPER_ID)
);

DROP INDEX IF EXISTS CLIENTS_PROTOCOLS_MAPPERS_REALM_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_PROTOCOLS_MAPPERS_CLIENT_SCOPE_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_PROTOCOLS_MAPPERS_MAPPER_ID_IDX;

CREATE INDEX CLIENTS_PROTOCOLS_MAPPERS_REALM_ID_IDX ON CLIENTS_PROTOCOLS_MAPPERS(REALM_ID);
CREATE INDEX CLIENTS_PROTOCOLS_MAPPERS_CLIENT_ID_IDX ON CLIENTS_PROTOCOLS_MAPPERS(CLIENT_ID);
CREATE INDEX CLIENTS_PROTOCOLS_MAPPERS_MAPPER_ID_IDX ON CLIENTS_PROTOCOLS_MAPPERS(MAPPER_ID);


/*********************************************************************************************************
*                                             CLIENT_SCOPES_ROLES Table
**********************************************************************************************************/

CREATE TABLE IF NOT EXISTS CLIENTS_SCOPES_ROLES
(
    REALM_ID                                   varchar(250)            NOT NULL,
    CLIENT_SCOPE_ID                            varchar(250)             NOT NULL,
    ROLE_ID                                    varchar(250)             NOT NULL,

    CONSTRAINT FK_REALMS_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_CLIENT_SCOPE_ID FOREIGN KEY(CLIENT_SCOPE_ID) REFERENCES CLIENTS_SCOPES(CLIENT_SCOPE_ID) ON DELETE CASCADE,
    CONSTRAINT FK_ROLE_ID FOREIGN KEY(ROLE_ID) REFERENCES ROLES(ROLE_ID) ON DELETE CASCADE,


    CONSTRAINT UNIQUE_CLIENT_SCOPES_ROLES_REALM_ID_CLIENT_SCOPE_ID_ROLE_ID UNIQUE (REALM_ID, CLIENT_SCOPE_ID, ROLE_ID)
);

DROP INDEX IF EXISTS CLIENTS_SCOPES_ROLES_REALM_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_SCOPES_ROLES_CLIENT_SCOPE_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_SCOPES_ROLES_ROLE_ID_IDX;

CREATE INDEX CLIENTS_SCOPES_ROLES_REALM_ID_IDX ON CLIENTS_SCOPES_ROLES(REALM_ID);
CREATE INDEX CLIENTS_SCOPES_ROLES_CLIENT_SCOPE_ID_IDX ON CLIENTS_SCOPES_ROLES(CLIENT_SCOPE_ID);
CREATE INDEX CLIENTS_SCOPES_ROLES_ROLE_ID_IDX ON CLIENTS_SCOPES_ROLES(ROLE_ID);


/*********************************************************************************************************
*                                       CLIENTS_SCOPES_PROTOCOLS_MAPPERS Table
**********************************************************************************************************/

CREATE TABLE IF NOT EXISTS CLIENTS_SCOPES_PROTOCOLS_MAPPERS
(
    REALM_ID                                   varchar(250)             NOT NULL,
    CLIENT_SCOPE_ID                            varchar(250)             NOT NULL,
    MAPPER_ID                                  varchar(250)             NOT NULL,

    CONSTRAINT FK_REALMS_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_CLIENT_SCOPE_ID FOREIGN KEY(CLIENT_SCOPE_ID) REFERENCES CLIENTS_SCOPES(CLIENT_SCOPE_ID) ON DELETE CASCADE,
    CONSTRAINT FK_MAPPER_ID FOREIGN KEY(MAPPER_ID) REFERENCES PROTOCOLS_MAPPERS(MAPPER_ID) ON DELETE CASCADE,

    CONSTRAINT UNIQUE_CLIENT_SCOPE_MAPPERS_ID_MAPPER_ID UNIQUE (REALM_ID, CLIENT_SCOPE_ID, MAPPER_ID)
);

DROP INDEX IF EXISTS CLIENTS_SCOPES_PROTOCOLS_MAPPERS_REALM_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_SCOPES_PROTOCOLS_MAPPERS_CLIENT_SCOPE_ID_IDX;
DROP INDEX IF EXISTS CLIENTS_SCOPES_PROTOCOLS_MAPPERS_MAPPER_ID_IDX;

CREATE INDEX CLIENTS_SCOPES_PROTOCOLS_MAPPERS_REALM_ID_IDX ON CLIENTS_SCOPES_PROTOCOLS_MAPPERS(REALM_ID);
CREATE INDEX CLIENTS_SCOPES_PROTOCOLS_MAPPERS_CLIENT_SCOPE_ID_IDX ON CLIENTS_SCOPES_PROTOCOLS_MAPPERS(CLIENT_SCOPE_ID);
CREATE INDEX CLIENTS_SCOPES_PROTOCOLS_MAPPERS_MAPPER_ID_IDX ON CLIENTS_SCOPES_PROTOCOLS_MAPPERS(MAPPER_ID);



/***********************************************************************************************************
*                                           AUTHENTICATION_FLOW Table
************************************************************************************************************/

CREATE TABLE IF NOT EXISTS AUTHENTICATION_FLOW
(
    ID                                   serial                  PRIMARY KEY,
    TENANT                               varchar(50)             NOT NULL,
    REALM_ID                             varchar(250)            NOT NULL,
    FLOW_ID                              varchar(50)             UNIQUE NOT NULL,

    ALIAS                                TEXT,
    PROVIDER_ID                          TEXT,
    DESCRIPTION                          TEXT,
    TOP_LEVEL                            boolean,
    BUILT_IN                             boolean,

    CREATED_BY                           varchar(250)            NOT NULL,
    CREATED_AT                           timestamptz             NOT NULL,
    UPDATED_BY                           varchar(250),
    UPDATED_AT                           timestamptz,
    VERSION                              integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_AUTHENTICATION_FLOW_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE
);

DROP INDEX IF EXISTS AUTHENTICATION_FLOW_FLOW_ID_IDX;
DROP INDEX IF EXISTS AUTHENTICATION_FLOW_REALM_ID_IDX;
DROP INDEX IF EXISTS AUTHENTICATION_FLOW_PROVIDER_ID_IDX;
DROP INDEX IF EXISTS AUTHENTICATION_FLOW_ALIAS_IDX;

CREATE INDEX AUTHENTICATION_FLOW_FLOW_ID_IDX ON AUTHENTICATION_FLOW(FLOW_ID);
CREATE INDEX AUTHENTICATION_FLOW_REALM_ID_IDX ON AUTHENTICATION_FLOW(REALM_ID);
CREATE INDEX AUTHENTICATION_FLOW_PROVIDER_ID_IDX ON AUTHENTICATION_FLOW(PROVIDER_ID);
CREATE INDEX AUTHENTICATION_FLOW_ALIAS_IDX ON AUTHENTICATION_FLOW(ALIAS);


/***********************************************************************************
*                           AUTHENTICATION_CONFIG Table
************************************************************************************/

CREATE TABLE IF NOT EXISTS AUTHENTICATION_CONFIG
(
    ID                                   serial                  PRIMARY KEY,
    TENANT                               varchar(50)             NOT NULL,
    REALM_ID                             varchar(250)            NOT NULL,
    CONFIG_ID                            varchar(50)             UNIQUE NOT NULL,

    ALIAS                                TEXT,
    CONFIGS                              json,

    CREATED_BY                           varchar(250)            NOT NULL,
    CREATED_AT                           timestamptz             NOT NULL,
    UPDATED_BY                           varchar(250),
    UPDATED_AT                           timestamptz,
    VERSION                              integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_AUTHENTICATOR_CONFIG_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE

);

DROP INDEX IF EXISTS AUTHENTICATOR_CONFIG_CONFIG_ID_IDX;
DROP INDEX IF EXISTS AUTHENTICATOR_CONFIG_REALM_ID_IDX;
DROP INDEX IF EXISTS AUTHENTICATOR_CONFIG_ALIAS_IDX;

CREATE INDEX AUTHENTICATOR_CONFIG_CONFIG_ID_IDX ON AUTHENTICATOR_CONFIG(CONFIG_ID);
CREATE INDEX AUTHENTICATOR_CONFIG_REALM_ID_IDX ON AUTHENTICATOR_CONFIG(REALM_ID);
CREATE INDEX AUTHENTICATOR_CONFIG_ALIAS_IDX ON AUTHENTICATOR_CONFIG(ALIAS);


/*********************************************************************************************************************
*                           AUTHENTICATION_EXECUTION Table
**********************************************************************************************************************/

CREATE TABLE IF NOT EXISTS AUTHENTICATION_EXECUTION
(
    ID                                   serial                  PRIMARY KEY,
    TENANT                               varchar(50)             NOT NULL,

    EXECUTION_ID                         varchar(50)             UNIQUE NOT NULL,
    ALIAS                                varchar(50)             NOT NULL,
    REALM_ID                             varchar(250)            NOT NULL,
    FLOW_ID                              varchar(250)            NOT NULL,
    PARENT_FLOW_ID                       varchar(250)            NOT NULL,
    AUTHENTICATOR                        TEXT                    NOT NULL,

    REQUIREMENT                          AuthenticatorRequirementEnum,
    AUTHENTICATOR_CONFIG_ID              varchar(50),
    PRIORITY                             integer,
    AUTHENTICATOR_FLOW                   boolean,

    CREATED_BY                           varchar(250)            NOT NULL,
    CREATED_AT                           timestamptz             NOT NULL,
    UPDATED_BY                           varchar(250),
    UPDATED_AT                           timestamptz,
    VERSION                              integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_AUTHENTICATION_EXECUTION_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE
);

DROP INDEX IF EXISTS AUTHENTICATION_EXECUTION_EXEC_ID_IDX;
DROP INDEX IF EXISTS AUTHENTICATION_EXECUTION_REALM_ID_IDX;
DROP INDEX IF EXISTS AUTHENTICATION_EXECUTION_FLOW_ID_IDX;
DROP INDEX IF EXISTS AUTHENTICATION_EXECUTION_PARENT_FLOW_ID_IDX;
DROP INDEX IF EXISTS AUTHENTICATION_EXECUTION_AUTHENTICATOR_FLOW_IDX;

CREATE INDEX AUTHENTICATION_EXECUTION_EXEC_ID_IDX ON AUTHENTICATION_EXECUTION(EXECUTION_ID);
CREATE INDEX AUTHENTICATION_EXECUTION_REALM_ID_IDX ON AUTHENTICATION_EXECUTION(REALM_ID);
CREATE INDEX AUTHENTICATION_EXECUTION_FLOW_ID_IDX ON AUTHENTICATION_EXECUTION(FLOW_ID);
CREATE INDEX AUTHENTICATION_EXECUTION_PARENT_FLOW_ID_IDX ON AUTHENTICATION_EXECUTION(PARENT_FLOW_ID);
CREATE INDEX AUTHENTICATION_EXECUTION_AUTHENTICATOR_FLOW_IDX ON AUTHENTICATION_EXECUTION(AUTHENTICATOR_FLOW);


/***********************************************************************************
*                            REVOKED_TOKENS Table
************************************************************************************/

CREATE TABLE IF NOT EXISTS REVOKED_TOKENS
(
    ID                                   serial                  PRIMARY KEY,
    TENANT                               varchar(250)            NOT NULL,
    REALM_ID                             varchar(250)            NOT NULL,
    TOKEN_ID                             text,
    REVOKATION_TIME                      numeric,
    LIFE_SPAN_IN_SECS                    numeric,

    CONSTRAINT FK_REVOKED_TOKENS_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE
);

DROP INDEX IF EXISTS REVOKED_TOKENS_TOKEN_ID_IDX;
DROP INDEX IF EXISTS REVOKED_TOKENS_REALM_ID_IDX;
DROP INDEX IF EXISTS REVOKED_TOKENS_TENANT_IDX;

CREATE INDEX REVOKED_TOKENS_TOKEN_ID_IDX ON REVOKED_TOKENS(REALM_ID);
CREATE INDEX REVOKED_TOKENS_REALM_ID_IDX ON REVOKED_TOKENS(TOKEN_ID);
CREATE INDEX REVOKED_TOKENS_TENANT_IDX ON REVOKED_TOKENS(TENANT);


/***********************************************************************************
*                            REVOKED_TOKENS Table
************************************************************************************/

CREATE TABLE IF NOT EXISTS SINGLE_USE_TOKENS
(
    ID                                   serial                  PRIMARY KEY,
    TENANT                               varchar(250)            NOT NULL,
    REALM_ID                             varchar(250)            NOT NULL,
    TOKEN_ID                             text,
    LIFE_SPAN_IN_SECS                    numeric,

    CONSTRAINT FK_SINGLE_USE_TOKENS_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE
);

DROP INDEX IF EXISTS SINGLE_USE_TOKENS_REALM_ID_IDX;
DROP INDEX IF EXISTS SINGLE_USE_TOKENS_TOKEN_ID_IDX;
DROP INDEX IF EXISTS SINGLE_USE_TOKENS_TENANT_IDX;

CREATE INDEX SINGLE_USE_TOKENS_REALM_ID_IDX ON SINGLE_USE_TOKENS(REALM_ID);
CREATE INDEX SINGLE_USE_TOKENS_TOKEN_ID_IDX ON SINGLE_USE_TOKENS(TOKEN_ID);
CREATE INDEX SINGLE_USE_TOKENS_TENANT_IDX ON SINGLE_USE_TOKENS(TENANT);

/***********************************************************************************
*                            USER_LOGIN_FAILURES Table
************************************************************************************/

CREATE TABLE IF NOT EXISTS USER_LOGIN_FAILURES
(
    ID                                   serial                  PRIMARY KEY,
    TENANT                               varchar(250)            NOT NULL,
    FAILURE_ID                           varchar(50)             NOT NULL,
    USER_ID                              varchar(250)            NOT NULL,
    REALM_ID                             varchar(250)            NOT NULL,
    FAILED_LOGIN_NOT_BEFORE              numeric,
    NUM_FAILURE                          integer,
    LAST_FAILURE                         numeric,
    LAST_IP_FAILURE                      varchar(20),

    CONSTRAINT FK_USER_LOGIN_FAILURES_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT UNIQUE_USER_LOGIN_FAILURES_REALM_ID_USER_ID UNIQUE (REALM_ID, USER_ID)
);

DROP INDEX IF EXISTS USER_LOGIN_FAILURES_FAILURE_ID_IDX;
DROP INDEX IF EXISTS USER_LOGIN_FAILURES_USER_ID_IDX;
DROP INDEX IF EXISTS USER_LOGIN_FAILURES_REALM_ID_IDX;
DROP INDEX IF EXISTS USER_LOGIN_FAILURES_TENANT_IDX;

CREATE INDEX USER_LOGIN_FAILURES_FAILURE_ID_IDX ON USER_LOGIN_FAILURES(FAILURE_ID);
CREATE INDEX USER_LOGIN_FAILURES_USER_ID_IDX ON USER_LOGIN_FAILURES(USER_ID);
CREATE INDEX USER_LOGIN_FAILURES_REALM_ID_IDX ON USER_LOGIN_FAILURES(REALM_ID);
CREATE INDEX USER_LOGIN_FAILURES_TENANT_IDX ON USER_LOGIN_FAILURES(TENANT);


/***********************************************************************************
*                           USERS Table
************************************************************************************/

CREATE TABLE IF NOT EXISTS USERS
(
    ID                                    serial                  PRIMARY KEY,
    TENANT                                varchar(50)             NOT NULL,
    REALM_ID                              varchar(250)            NOT NULL,
    USER_ID                               varchar(250)            UNIQUE NOT NULL,
    USER_NAME                             varchar(250)            NOT NULL,

    EMAIL                                 varchar(250),
    ENABLED                               boolean,
    EMAIL_VERIFIED                        boolean,

    IS_SERVICE_ACCOUNT                    boolean,
    USER_STORAGE                          TEXT,
    ATTRIBUTES                            JSON,
    NOT_BEFORE                            integer,
    REQUIRED_ACTIONS                      TEXT[],
    SERVICE_ACCOUNT_CLIENT_LINK           TEXT,

    CREATED_BY                            varchar(250)            NOT NULL,
    CREATED_AT                            timestamptz             NOT NULL,
    UPDATED_BY                            varchar(250),
    UPDATED_AT                            timestamptz,
    VERSION                               integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_USERS_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT UNIQUE_USERS_REALM_ID_USER_ID UNIQUE (REALM_ID, USER_ID)
);

DROP INDEX IF EXISTS USERS_REALM_ID_IDX;
DROP INDEX IF EXISTS USERS_USER_ID_IDX;
DROP INDEX IF EXISTS USERS_USER_NAME_IDX;
DROP INDEX IF EXISTS USERS_EMAIL_IDX;
DROP INDEX IF EXISTS USERS_IS_SERVICE_ACCOUNT_IDX;

CREATE INDEX USERS_REALM_ID_IDX ON USERS(REALM_ID);
CREATE INDEX USERS_USER_ID_IDX ON USERS(USER_ID);
CREATE INDEX USERS_USER_NAME_IDX ON USERS(USER_NAME);
CREATE INDEX USERS_EMAIL_IDX ON USERS(EMAIL);
CREATE INDEX USERS_IS_SERVICE_ACCOUNT_IDX ON USERS(IS_SERVICE_ACCOUNT);


/************************************************************************************************************
*                                          USERS_CONSENTS Table
************************************************************************************************************/

CREATE TABLE IF NOT EXISTS USERS_CREDENTIALS
(
    ID                                  serial                  PRIMARY KEY,
    REALM_ID                            varchar(250)            NOT NULL,
    CREDENTIAL_ID                       varchar(250)            UNIQUE NOT NULL,
    USER_ID                             varchar(250)            NOT NULL,
    CREDENTIAL_TYPE                     varchar(20),

    USER_LABEL                          varchar(100),
    SECRET_DATA                         json,
    CREDENTIAL_DATA                     json,
    PRIORITY                            NUMERIC,

    CREATED_BY                          varchar(250)            NOT NULL,
    CREATED_AT                          timestamptz             NOT NULL,
    UPDATED_BY                          varchar(250),
    UPDATED_AT                          timestamptz,
    VERSION                             integer                 DEFAULT 1   CHECK(version > 0),

    CONSTRAINT FK_USERS_CREDENTIALS_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_USERS_CREDENTIALS_USER_ID  FOREIGN KEY(USER_ID) REFERENCES USERS(USER_ID) ON DELETE CASCADE,
    CONSTRAINT UNIQUE_USERS_CREDENTIALS_REALM_ID_USER_ID_CREDENTIAL_ID UNIQUE (REALM_ID, USER_ID, CREDENTIAL_ID)
);

DROP INDEX IF EXISTS USERS_CREDENTIALS_REALM_ID_IDX;
DROP INDEX IF EXISTS USERS_CREDENTIALS_USER_ID_IDX;
DROP INDEX IF EXISTS USERS_CREDENTIALS_CREDENTIAL_ID_IDX;
DROP INDEX IF EXISTS USERS_CREDENTIALS_CREDENTIAL_TYPE_ID;
DROP INDEX IF EXISTS USERS_CREDENTIALS_PRIORITY_ID;

CREATE INDEX USERS_CREDENTIALS_REALM_ID_IDX ON USERS_CREDENTIALS(REALM_ID);
CREATE INDEX USERS_CREDENTIALS_USER_ID_IDX ON USERS_CREDENTIALS(USER_ID);
CREATE INDEX USERS_CREDENTIALS_CREDENTIAL_ID_IDX ON USERS_CREDENTIALS(CREDENTIAL_ID);
CREATE INDEX USERS_CREDENTIALS_CREDENTIAL_TYPE_ID ON USERS_CREDENTIALS(CREDENTIAL_TYPE);
CREATE INDEX USERS_CREDENTIALS_PRIORITY_ID ON USERS_CREDENTIALS(PRIORITY);

/*******************************************************************************************************************
*                                       USERS_GROUPS Table
********************************************************************************************************************/

CREATE TABLE IF NOT EXISTS USERS_GROUPS
(
    REALM_ID                                   varchar(250)             NOT NULL,
    USER_ID                                    varchar(250)             NOT NULL,
    GROUP_ID                                   varchar(250)             NOT NULL,

    CONSTRAINT FK_USERS_GROUPS_REALMS_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_USERS_GROUPS_USER_ID FOREIGN KEY(USER_ID) REFERENCES USERS(USER_ID) ON DELETE CASCADE,
    CONSTRAINT FK_USERS_GROUPS_GROUP_ID FOREIGN KEY(GROUP_ID) REFERENCES GROUPS(GROUP_ID) ON DELETE CASCADE,

    CONSTRAINT UNIQUE_USERS_GROUPS_REALM_ID_USER_ID_GROUP_ID UNIQUE (REALM_ID, USER_ID, GROUP_ID)
);

DROP INDEX IF EXISTS USERS_GROUPS_REALM_ID_IDX;
DROP INDEX IF EXISTS USERS_GROUPS_USER_ID_IDX;
DROP INDEX IF EXISTS USERS_GROUPS_GROUP_ID_IDX;

CREATE INDEX USERS_GROUPS_REALM_ID_IDX ON USERS_GROUPS(REALM_ID);
CREATE INDEX USERS_GROUPS_USER_ID_IDX ON USERS_GROUPS(USER_ID);
CREATE INDEX USERS_GROUPS_GROUP_ID_IDX ON USERS_GROUPS(GROUP_ID);


/*******************************************************************************************************************
*                                       USERS_ROLES Table
********************************************************************************************************************/

CREATE TABLE IF NOT EXISTS USERS_ROLES
(
    REALM_ID                                   varchar(250)              NOT NULL,
    USER_ID                                    varchar(250)              NOT NULL,
    ROLE_ID                                    varchar(250)              NOT NULL,

    CONSTRAINT FK_USERS_ROLES_REALM_ID FOREIGN KEY(REALM_ID) REFERENCES REALMS(REALM_ID) ON DELETE CASCADE,
    CONSTRAINT FK_USERS_ROLES_USER_ID FOREIGN KEY(USER_ID) REFERENCES USERS(USER_ID) ON DELETE CASCADE,
    CONSTRAINT FK_USERS_ROLES_ROLE_ID FOREIGN KEY(ROLE_ID) REFERENCES ROLES(ROLE_ID) ON DELETE CASCADE,

    CONSTRAINT UNIQUE_USER_ID_ROLE_ID UNIQUE (REALM_ID, USER_ID, ROLE_ID)
);

DROP INDEX IF EXISTS USERS_ROLES_REALM_ID_IDX;
DROP INDEX IF EXISTS USERS_ROLES_USER_ID_IDX;
DROP INDEX IF EXISTS USERS_ROLES_ROLE_ID_IDX;

CREATE INDEX USERS_ROLES_REALM_ID_IDX ON USERS_ROLES(REALM_ID);
CREATE INDEX USERS_ROLES_USER_ID_IDX ON USERS_ROLES(USER_ID);
CREATE INDEX USERS_ROLES_ROLE_ID_IDX ON USERS_ROLES(ROLE_ID);
