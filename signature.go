package go_signature_sdk

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

// Config SDK配置
type Config struct {
	DB *sql.DB
}

// AppKey 应用密钥信息
type AppKey struct {
	ID        int      `json:"id"`
	AppID     string   `json:"app_id"`
	SecretKey string   `json:"secret_key"`
	IPsWhite  []string `json:"ips_white"`
	Status    int      `json:"status"`
	CreateAt  int64    `json:"create_at"`
	UpdateAt  *int64   `json:"update_at"`
}

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

// SignParams 签名参数
type SignParams struct {
	AppID string            `json:"app_id"`
	Data  map[string]string `json:"data"`
}

// VerifyParams 验签参数
type VerifyParams struct {
	AppID    string            `json:"app_id"`
	Data     map[string]string `json:"data"`
	ClientIP string            `json:"client_ip"`
}

// 错误定义
var (
	ErrAppNotFound    = errors.New("应用不存在")
	ErrAppDisabled    = errors.New("应用已禁用")
	ErrIPNotAllowed   = errors.New("IP不在白名单中")
	ErrInvalidSign    = errors.New("签名验证失败")
	ErrExpiredRequest = errors.New("请求已过期")
)

// GetAppKey 根据app_id获取应用密钥信息
func (s *SignatureSDK) GetAppKey(appID string) (*AppKey, error) {
	query := `
		SELECT id, app_id, secret_key, ips_white, status, create_at, update_at
		FROM app_keys 
		WHERE app_id = $1
	`

	row := s.db.QueryRow(query, appID)

	var appKey AppKey
	var ipsWhiteJSON []byte
	var updateAt sql.NullInt64

	err := row.Scan(
		&appKey.ID,
		&appKey.AppID,
		&appKey.SecretKey,
		&ipsWhiteJSON,
		&appKey.Status,
		&appKey.CreateAt,
		&updateAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("查询应用密钥失败: %w", err)
	}

	// 解析IP白名单JSON
	if err := json.Unmarshal(ipsWhiteJSON, &appKey.IPsWhite); err != nil {
		return nil, fmt.Errorf("解析IP白名单失败: %w", err)
	}

	if updateAt.Valid {
		appKey.UpdateAt = &updateAt.Int64
	}

	return &appKey, nil
}

// GenerateSign 生成签名
func (s *SignatureSDK) GenerateSign(params *SignParams) error {
	// 获取应用密钥
	appKey, err := s.GetAppKey(params.AppID)
	if err != nil {
		return err
	}

	if appKey.Status != 1 {
		return ErrAppDisabled
	}

	// 构建签名字符串
	signStr := s.buildSignString(params.Data, appKey.SecretKey)
	params.Data["sign"] = s.md5Hash(signStr)
	return nil
}

// VerifySign 验证签名
func (s *SignatureSDK) VerifySign(params *VerifyParams) error {
	// 获取应用密钥
	appKey, err := s.GetAppKey(params.AppID)
	if err != nil {
		return err
	}

	if appKey.Status != 1 {
		return ErrAppDisabled
	}

	// 验证IP白名单
	if err := s.verifyIPWhitelist(params.ClientIP, appKey.IPsWhite); err != nil {
		return err
	}
	sign := params.Data["sign"]
	params.Data["sign"] = ""
	// 构建签名字符串
	signStr := s.buildSignString(params.Data, appKey.SecretKey)
	// 生成签名并比较
	expectedSign := s.md5Hash(signStr)
	if expectedSign != sign {
		return ErrInvalidSign
	}

	return nil
}

// buildSignString 构建签名字符串
func (s *SignatureSDK) buildSignString(data map[string]string, secretKey string) string {
	// 添加系统参数
	allParams := make(map[string]string)
	for k, v := range data {
		allParams[k] = v
	}

	// 获取所有键并按ASCII码排序
	keys := make([]string, 0, len(allParams))
	for k := range allParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 构建签名字符串
	var signParts []string
	for _, k := range keys {
		if allParams[k] != "" { // 跳过空值
			signParts = append(signParts, fmt.Sprintf("%s=%s", k, allParams[k]))
		}
	}

	signStr := strings.Join(signParts, "&") + "&key=" + secretKey
	return signStr
}

// md5Hash 生成MD5哈希
func (s *SignatureSDK) md5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// verifyIPWhitelist 验证IP白名单
func (s *SignatureSDK) verifyIPWhitelist(clientIP string, whitelist []string) error {
	if len(whitelist) == 0 {
		return nil // 如果白名单为空，则不限制
	}

	clientIPAddr := net.ParseIP(clientIP)
	if clientIPAddr == nil {
		return fmt.Errorf("无效的客户端IP: %s", clientIP)
	}

	for _, whiteIP := range whitelist {
		// 支持单个IP和CIDR格式
		if strings.Contains(whiteIP, "/") {
			// CIDR格式
			_, ipNet, err := net.ParseCIDR(whiteIP)
			if err != nil {
				continue
			}
			if ipNet.Contains(clientIPAddr) {
				return nil
			}
		} else {
			// 单个IP
			if whiteIP == clientIP {
				return nil
			}
		}
	}

	return ErrIPNotAllowed
}

// CreateAppKey 创建应用密钥
func (s *SignatureSDK) CreateAppKey(appID, secretKey string, ipsWhite []string) error {
	ipsWhiteJSON, err := json.Marshal(ipsWhite)
	if err != nil {
		return fmt.Errorf("序列化IP白名单失败: %w", err)
	}

	query := `
		INSERT INTO app_keys (app_id, secret_key, ips_white, status, create_at)
		VALUES ($1, $2, $3, 1, $4)
	`

	_, err = s.db.Exec(query, appID, secretKey, ipsWhiteJSON, time.Now().Unix())
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return fmt.Errorf("应用ID已存在: %s", appID)
		}
		return fmt.Errorf("创建应用密钥失败: %w", err)
	}

	return nil
}

// UpdateAppKey 更新应用密钥
func (s *SignatureSDK) UpdateAppKey(appID, secretKey string, ipsWhite []string, status int) error {
	ipsWhiteJSON, err := json.Marshal(ipsWhite)
	if err != nil {
		return fmt.Errorf("序列化IP白名单失败: %w", err)
	}

	query := `
		UPDATE app_keys 
		SET secret_key = $2, ips_white = $3, status = $4, update_at = $5
		WHERE app_id = $1
	`

	result, err := s.db.Exec(query, appID, secretKey, ipsWhiteJSON, status, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("更新应用密钥失败: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("获取更新行数失败: %w", err)
	}

	if rowsAffected == 0 {
		return ErrAppNotFound
	}

	return nil
}
