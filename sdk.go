package go_signature_sdk

import (
	"database/sql"
	"log"
)

// SignatureSDK 签名SDK
type SignatureSDK struct {
	db *sql.DB
}

// NewSignatureSDK 创建签名SDK实例
func NewSignatureSDK(config *Config) *SignatureSDK {
	query := `CREATE TABLE IF NOT EXISTS app_keys (	
    id SERIAL PRIMARY KEY,
    app_id VARCHAR(32) NOT NULL UNIQUE,
    secret_key VARCHAR(64) NOT NULL,
    ips_white JSONB NOT NULL,
    status SMALLINT NOT NULL DEFAULT 1,
    attributes JSONB NOT NULL DEFAULT '{}',
    create_at BIGINT NOT NULL,
    update_at BIGINT DEFAULT NULL); 
CREATE INDEX IF NOT EXISTS  idx_app_keys_app_id ON app_keys(app_id);
CREATE INDEX  IF NOT EXISTS idx_app_keys_status ON app_keys(status);`
	if _, err := config.DB.Exec(query); err != nil {
		log.Println("failed to create app_keys table: %w", err)
	}

	return &SignatureSDK{
		db: config.DB,
	}
}

// GenerateSign 生成签名
func (s *SignatureSDK) GenerateSign(params *SignParams) (error, string) {
	// 获取应用密钥
	appKey, err := s.GetAppKey(params.AppID)
	if err != nil {
		return err, ""
	}

	if appKey.Status != 1 {
		return ErrAppDisabled, ""
	}

	// 构建签名字符串
	sign, s2 := GenerateSign(params.Data, appKey.SecretKey)
	params.Data["sign"] = sign
	return nil, s2
}

// VerifyIPs 验证IP和获取应用密钥
func (s *SignatureSDK) VerifyIPs(AppID, clientIP string) (*AppKey, error) {
	appKey, err := s.GetAppKey(AppID)
	if err != nil {
		return nil, err
	}

	if appKey.Status != 1 {
		return nil, ErrAppDisabled
	}

	// 验证IP白名单
	if err := s.verifyIPWhitelist(clientIP, appKey.IPsWhite); err != nil {
		return nil, err
	}
	return appKey, nil
}

// VerifySign 验证签名
func (s *SignatureSDK) VerifySign(params *VerifyParams) error {
	// 获取应用密钥
	appKey, err := s.VerifyIPs(params.AppID, params.ClientIP)
	if err != nil {
		return err
	}
	return VerifySign(params, appKey.SecretKey)
}
