-- 创建应用密钥表
CREATE TABLE IF NOT EXISTS app_keys (
                                        id SERIAL PRIMARY KEY,
                                        app_id VARCHAR(32) NOT NULL UNIQUE,
    secret_key VARCHAR(64) NOT NULL,
    ips_white JSONB NOT NULL,
    status SMALLINT NOT NULL DEFAULT 1,
    create_at BIGINT NOT NULL,
    update_at BIGINT DEFAULT NULL
    );

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_app_keys_app_id ON app_keys(app_id);
CREATE INDEX IF NOT EXISTS idx_app_keys_status ON app_keys(status);

-- 添加注释
COMMENT ON TABLE app_keys IS '应用密钥表';
COMMENT ON COLUMN app_keys.app_id IS '应用ID';
COMMENT ON COLUMN app_keys.secret_key IS '密钥';
COMMENT ON COLUMN app_keys.ips_white IS 'ip白名单';
COMMENT ON COLUMN app_keys.status IS '状态 1:启用 0:禁用';
COMMENT ON COLUMN app_keys.create_at IS '创建时间戳';
COMMENT ON COLUMN app_keys.update_at IS '更新时间戳';

-- 插入示例数据（可选）
INSERT INTO app_keys (app_id, secret_key, ips_white, status, create_at)
VALUES
    ('demo_app', 'demo_secret_key_123', '["127.0.0.1", "192.168.1.0/24"]', 1, EXTRACT(EPOCH FROM NOW()))
    ON CONFLICT (app_id) DO NOTHING;