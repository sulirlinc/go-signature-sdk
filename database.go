package go_signature_sdk

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lib/pq"
	"time"
)

// GetAppKey 根据app_id获取应用密钥信息
func (s *SignatureSDK) GetAppKey(appID string) (*AppKey, error) {
	query := `
		SELECT id, app_id, secret_key, ips_white, status, create_at, update_at, attributes
		FROM app_keys 
		WHERE app_id = $1
	`

	row := s.db.QueryRow(query, appID)

	var appKey AppKey
	var ipsWhiteJSON []byte
	var attributesJSON []byte
	var updateAt sql.NullInt64

	err := row.Scan(
		&appKey.ID,
		&appKey.AppID,
		&appKey.SecretKey,
		&ipsWhiteJSON,
		&appKey.Status,
		&appKey.CreateAt,
		&updateAt,
		&attributesJSON,
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

	// 解析Attributes
	if err := json.Unmarshal(attributesJSON, &appKey.Attributes); err != nil {
		return nil, fmt.Errorf("解析Attributes失败: %w", err)
	}

	if updateAt.Valid {
		appKey.UpdateAt = &updateAt.Int64
	}

	return &appKey, nil
}

// CreateAppKey 创建应用密钥
func (s *SignatureSDK) CreateAppKey(appID, secretKey string, ipsWhite []string, attributes map[string]interface{}) error {
	ipsWhiteJSON, err := json.Marshal(ipsWhite)
	if err != nil {
		return fmt.Errorf("序列化IP白名单失败: %w", err)
	}

	query := `
		INSERT INTO app_keys (app_id, secret_key, ips_white, status, create_at, attributes)
		VALUES ($1, $2, $3, 1, $4, $5)
	`
	d, _ := json.Marshal(attributes)
	_, err = s.db.Exec(query, appID, secretKey, ipsWhiteJSON, time.Now().Unix(), d)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return fmt.Errorf("应用ID已存在: %s", appID)
		}
		return fmt.Errorf("创建应用密钥失败: %w", err)
	}

	return nil
}

// UpdateAppKey 更新应用密钥
func (s *SignatureSDK) UpdateAppKey(appID, secretKey string, ipsWhite []string, status int, attributes map[string]interface{}) error {
	ipsWhiteJSON, err := json.Marshal(ipsWhite)
	if err != nil {
		return fmt.Errorf("序列化IP白名单失败: %w", err)
	}

	query := `
		UPDATE app_keys 
		SET secret_key = $2, ips_white = $3, status = $4, update_at = $5, attributes = $6
		WHERE app_id = $1
	`
	d, _ := json.Marshal(attributes)
	result, err := s.db.Exec(query, appID, secretKey, ipsWhiteJSON, status, time.Now().Unix(), d)
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
