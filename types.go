package go_signature_sdk

import "database/sql"

// Config SDK配置
type Config struct {
	DB *sql.DB
}

// AppKey 应用密钥信息
type AppKey struct {
	ID         int                    `json:"id"`
	AppID      string                 `json:"app_id"`
	SecretKey  string                 `json:"secret_key"`
	IPsWhite   []string               `json:"ips_white"`
	Status     int                    `json:"status"`
	CreateAt   int64                  `json:"create_at"`
	UpdateAt   *int64                 `json:"update_at"`
	Attributes map[string]interface{} `json:"attributes"`
}

// SignParams 签名参数
type SignParams struct {
	AppID string                 `json:"app_id"`
	Data  map[string]interface{} `json:"data"`
}

// VerifyParams 验签参数
type VerifyParams struct {
	AppID    string                 `json:"app_id"`
	Data     map[string]interface{} `json:"data"`
	ClientIP string                 `json:"client_ip"`
}
