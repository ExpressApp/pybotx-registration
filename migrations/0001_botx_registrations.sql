CREATE TABLE botx_registrations (
    server_id VARCHAR(256) NOT NULL,
    bot_id VARCHAR(256) NOT NULL,
    server_host VARCHAR(2048) NOT NULL,
    status VARCHAR(32) NOT NULL,
    secret_revision BIGINT NOT NULL,
    storage_ciphertext BYTEA,
    storage_key_id VARCHAR(256),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_botx_registrations PRIMARY KEY (server_id, bot_id),
    CONSTRAINT ck_botx_registrations_revision CHECK (secret_revision > 0),
    CONSTRAINT ck_botx_registrations_status CHECK (
        status IN ('AWAITING_REGISTRATION', 'ACTIVE', 'DEACTIVATED')
    ),
    CONSTRAINT ck_botx_registrations_active_secret CHECK (
        (status <> 'ACTIVE')
        OR (storage_ciphertext IS NOT NULL AND storage_key_id IS NOT NULL)
    )
);

CREATE TABLE botx_key_material (
    name VARCHAR(128) PRIMARY KEY,
    root_key_id VARCHAR(128) NOT NULL,
    ciphertext BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
