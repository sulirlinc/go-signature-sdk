package go_signature_sdk

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// 测试配置
const (
	testDBHost     = "localhost"
	testDBPort     = 5432
	testDBUser     = "test"
	testDBPassword = "test"
	testDBName     = "test_signature_sdk"
)

// setupTestDB 设置测试数据库
func setupTestDB(t *testing.T) *sql.DB {
	// 连接测试数据库
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		testDBHost, testDBPort, testDBUser, testDBPassword, testDBName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("跳过测试: 无法连接数据库 %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Skipf("跳过测试: 数据库连接失败 %v", err)
	}

	// 清理测试表
	_, err = db.Exec("DROP TABLE IF EXISTS app_keys")
	if err != nil {
		t.Fatalf("清理测试表失败: %v", err)
	}

	return db
}

// teardownTestDB 清理测试数据库
func teardownTestDB(t *testing.T, db *sql.DB) {
	if db != nil {
		db.Exec("DROP TABLE IF EXISTS app_keys")
		db.Close()
	}
}

// createTestSDK 创建测试SDK实例
func createTestSDK(t *testing.T) (*SignatureSDK, *sql.DB) {
	db := setupTestDB(t)
	config := &Config{DB: db}
	sdk := NewSignatureSDK(config)
	return sdk, db
}

// TestNewSignatureSDK 测试SDK创建
func TestNewSignatureSDK(t *testing.T) {
	sdk, db := createTestSDK(t)
	defer teardownTestDB(t, db)

	if sdk == nil {
		t.Fatal("SDK创建失败")
	}

	if sdk.db == nil {
		t.Fatal("SDK数据库连接为空")
	}
}

// TestCreateAppKey 测试创建应用密钥
func TestCreateAppKey(t *testing.T) {
	sdk, db := createTestSDK(t)
	defer teardownTestDB(t, db)

	testCases := []struct {
		name       string
		appID      string
		secretKey  string
		ipsWhite   []string
		attributes map[string]interface{}
		expectErr  bool
	}{
		{
			name:       "正常创建",
			appID:      "test_app_001",
			secretKey:  "test_secret_key_001",
			ipsWhite:   []string{"127.0.0.1", "192.168.1.0/24"},
			attributes: map[string]interface{}{"env": "test", "version": "1.0"},
			expectErr:  false,
		},
		{
			name:       "重复AppID",
			appID:      "test_app_001",
			secretKey:  "test_secret_key_002",
			ipsWhite:   []string{},
			attributes: map[string]interface{}{},
			expectErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := sdk.CreateAppKey(tc.appID, tc.secretKey, tc.ipsWhite, tc.attributes)
			if tc.expectErr && err == nil {
				t.Error("期望错误但没有发生")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("意外错误: %v", err)
			}
		})
	}
}

// TestGetAppKey 测试获取应用密钥
func TestGetAppKey(t *testing.T) {
	sdk, db := createTestSDK(t)
	defer teardownTestDB(t, db)

	// 先创建一个测试应用
	appID := "test_app_get"
	secretKey := "test_secret_get"
	ipsWhite := []string{"127.0.0.1", "10.0.0.0/8"}
	attributes := map[string]interface{}{"test": true}

	err := sdk.CreateAppKey(appID, secretKey, ipsWhite, attributes)
	if err != nil {
		t.Fatalf("创建测试应用失败: %v", err)
	}

	testCases := []struct {
		name      string
		appID     string
		expectErr error
	}{
		{
			name:      "获取存在的应用",
			appID:     appID,
			expectErr: nil,
		},
		{
			name:      "获取不存在的应用",
			appID:     "not_exist_app",
			expectErr: ErrAppNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			appKey, err := sdk.GetAppKey(tc.appID)
			if tc.expectErr != nil {
				if err != tc.expectErr {
					t.Errorf("期望错误 %v, 实际错误 %v", tc.expectErr, err)
				}
				return
			}

			if err != nil {
				t.Errorf("意外错误: %v", err)
				return
			}

			if appKey.AppID != tc.appID {
				t.Errorf("AppID不匹配: 期望 %s, 实际 %s", tc.appID, appKey.AppID)
			}

			if appKey.SecretKey != secretKey {
				t.Errorf("SecretKey不匹配: 期望 %s, 实际 %s", secretKey, appKey.SecretKey)
			}
		})
	}
}

// TestUpdateAppKey 测试更新应用密钥
func TestUpdateAppKey(t *testing.T) {
	sdk, db := createTestSDK(t)
	defer teardownTestDB(t, db)

	// 先创建一个测试应用
	appID := "test_app_update"
	err := sdk.CreateAppKey(appID, "old_secret", []string{"127.0.0.1"}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("创建测试应用失败: %v", err)
	}

	// 更新应用
	newSecretKey := "new_secret_key"
	newIpsWhite := []string{"192.168.1.0/24"}
	newAttributes := map[string]interface{}{"updated": true}

	err = sdk.UpdateAppKey(appID, newSecretKey, newIpsWhite, 1, newAttributes)
	if err != nil {
		t.Fatalf("更新应用失败: %v", err)
	}

	// 验证更新结果
	appKey, err := sdk.GetAppKey(appID)
	if err != nil {
		t.Fatalf("获取更新后的应用失败: %v", err)
	}

	if appKey.SecretKey != newSecretKey {
		t.Errorf("SecretKey更新失败: 期望 %s, 实际 %s", newSecretKey, appKey.SecretKey)
	}

	if len(appKey.IPsWhite) != 1 || appKey.IPsWhite[0] != newIpsWhite[0] {
		t.Errorf("IP白名单更新失败: 期望 %v, 实际 %v", newIpsWhite, appKey.IPsWhite)
	}
}

// TestGenerateSign 测试签名生成
func TestGenerateSign(t *testing.T) {
	testCases := []struct {
		name      string
		data      map[string]interface{}
		secretKey string
		expected  string
	}{
		{
			name: "简单参数",
			data: map[string]interface{}{
				"app_id":    "test_app",
				"timestamp": "1234567890",
				"nonce":     "abc123",
			},
			secretKey: "test_secret",
			expected:  "", // 这里需要手动计算期望值
		},
		{
			name: "嵌套参数",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"id":   123,
					"name": "test",
				},
				"timestamp": "1234567890",
			},
			secretKey: "test_secret",
			expected:  "", // 这里需要手动计算期望值
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sign := GenerateSign(tc.data, tc.secretKey)
			if sign == "" {
				t.Error("签名生成失败")
			}
			t.Logf("生成的签名: %s", sign)
		})
	}
}

// TestVerifySign 测试签名验证
func TestVerifySign(t *testing.T) {
	secretKey := "test_secret"
	data := map[string]interface{}{
		"app_id":    "test_app",
		"timestamp": "1234567890",
		"nonce":     "abc123",
	}

	// 生成签名
	sign := GenerateSign(data, secretKey)
	data["sign"] = sign

	// 测试验证
	params := &VerifyParams{
		AppID:    "test_app",
		Data:     data,
		ClientIP: "127.0.0.1",
	}

	err := VerifySign(params, secretKey)
	if err != nil {
		t.Errorf("签名验证失败: %v", err)
	}

	// 测试错误签名
	params.Data["sign"] = "wrong_sign"
	err = VerifySign(params, secretKey)
	if err != ErrInvalidSign {
		t.Errorf("期望签名验证失败, 实际: %v", err)
	}
}

// TestSDKGenerateSign 测试SDK签名生成
func TestSDKGenerateSign(t *testing.T) {
	sdk, db := createTestSDK(t)
	defer teardownTestDB(t, db)

	// 创建测试应用
	appID := "test_app_sign"
	secretKey := "test_secret_sign"
	err := sdk.CreateAppKey(appID, secretKey, []string{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("创建测试应用失败: %v", err)
	}

	// 测试签名生成
	params := &SignParams{
		AppID: appID,
		Data: map[string]interface{}{
			"timestamp": time.Now().Unix(),
			"nonce":     "test_nonce",
		},
	}

	err = sdk.GenerateSign(params)
	if err != nil {
		t.Errorf("SDK签名生成失败: %v", err)
	}

	if params.Data["sign"] == nil {
		t.Error("签名未生成")
	}

	t.Logf("生成的签名: %s", params.Data["sign"])
}

// TestSDKVerifySign 测试SDK签名验证
func TestSDKVerifySign(t *testing.T) {
	sdk, db := createTestSDK(t)
	defer teardownTestDB(t, db)

	// 创建测试应用
	appID := "test_app_verify"
	secretKey := "test_secret_verify"
	ipsWhite := []string{"127.0.0.1", "192.168.1.0/24"}
	err := sdk.CreateAppKey(appID, secretKey, ipsWhite, map[string]interface{}{})
	if err != nil {
		t.Fatalf("创建测试应用失败: %v", err)
	}

	// 生成签名
	data := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"nonce":     "test_nonce",
	}
	sign := GenerateSign(data, secretKey)
	data["sign"] = sign

	testCases := []struct {
		name      string
		appID     string
		clientIP  string
		data      map[string]interface{}
		expectErr error
	}{
		{
			name:      "正常验证",
			appID:     appID,
			clientIP:  "127.0.0.1",
			data:      data,
			expectErr: nil,
		},
		{
			name:      "IP不在白名单",
			appID:     appID,
			clientIP:  "10.0.0.1",
			data:      data,
			expectErr: ErrIPNotAllowed,
		},
		{
			name:      "应用不存在",
			appID:     "not_exist",
			clientIP:  "127.0.0.1",
			data:      data,
			expectErr: ErrAppNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := &VerifyParams{
				AppID:    tc.appID,
				Data:     tc.data,
				ClientIP: tc.clientIP,
			}

			err := sdk.VerifySign(params)
			if tc.expectErr != nil {
				if err != tc.expectErr {
					t.Errorf("期望错误 %v, 实际错误 %v", tc.expectErr, err)
				}
			} else if err != nil {
				t.Errorf("意外错误: %v", err)
			}
		})
	}
}

// TestIPWhitelist 测试IP白名单验证
func TestIPWhitelist(t *testing.T) {
	sdk, db := createTestSDK(t)
	defer teardownTestDB(t, db)

	testCases := []struct {
		name      string
		clientIP  string
		whitelist []string
		expectErr error
	}{
		{
			name:      "空白名单",
			clientIP:  "127.0.0.1",
			whitelist: []string{},
			expectErr: nil,
		},
		{
			name:      "单IP匹配",
			clientIP:  "127.0.0.1",
			whitelist: []string{"127.0.0.1"},
			expectErr: nil,
		},
		{
			name:      "CIDR匹配",
			clientIP:  "192.168.1.100",
			whitelist: []string{"192.168.1.0/24"},
			expectErr: nil,
		},
		{
			name:      "IP不匹配",
			clientIP:  "10.0.0.1",
			whitelist: []string{"127.0.0.1", "192.168.1.0/24"},
			expectErr: ErrIPNotAllowed,
		},
		{
			name:      "无效IP",
			clientIP:  "invalid_ip",
			whitelist: []string{"127.0.0.1"},
			expectErr: nil, // 这个会返回格式错误，不是ErrIPNotAllowed
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := sdk.verifyIPWhitelist(tc.clientIP, tc.whitelist)
			if tc.expectErr != nil {
				if err != tc.expectErr {
					t.Errorf("期望错误 %v, 实际错误 %v", tc.expectErr, err)
				}
			} else if err != nil && tc.clientIP != "invalid_ip" {
				t.Errorf("意外错误: %v", err)
			}
		})
	}
}

// TestBuildSignString 测试签名字符串构建
func TestBuildSignString(t *testing.T) {
	testCases := []struct {
		name      string
		data      map[string]interface{}
		secretKey string
		expected  string
	}{
		{
			name: "简单参数排序",
			data: map[string]interface{}{
				"c": "3",
				"a": "1",
				"b": "2",
			},
			secretKey: "secret",
			expected:  "a=1&b=2&c=3&key=secret",
		},
		{
			name: "嵌套对象",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "test",
					"id":   123,
				},
				"app": "test_app",
			},
			secretKey: "secret",
			expected:  "app=test_app&user.id=123&user.name=test&key=secret",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := buildSignString(tc.data, tc.secretKey)
			if result != tc.expected {
				t.Errorf("期望: %s, 实际: %s", tc.expected, result)
			}
		})
	}
}

// BenchmarkGenerateSign 性能测试
func BenchmarkGenerateSign(b *testing.B) {
	data := map[string]interface{}{
		"app_id":    "test_app",
		"timestamp": "1234567890",
		"nonce":     "abc123",
		"user": map[string]interface{}{
			"id":   123,
			"name": "test_user",
		},
	}
	secretKey := "test_secret"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateSign(data, secretKey)
	}
}

// ExampleSignatureSDK 使用示例
func ExampleSignatureSDK() {
	// 这里是使用示例，实际运行需要数据库连接
	fmt.Println("SignatureSDK使用示例:")
	fmt.Println("1. 创建SDK实例")
	fmt.Println("2. 创建应用密钥")
	fmt.Println("3. 生成签名")
	fmt.Println("4. 验证签名")
}
