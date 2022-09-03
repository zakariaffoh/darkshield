/*********************************************************************************************
*                                         SSLEnforcement Enum
**********************************************************************************************/
CREATE TYPE SslEnforcementEnum  AS ENUM ("NONE","ALL","EXTERNAL");

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
