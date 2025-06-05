package go_signature_sdk

import (
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

// TestSignatureSDK_GenerateSign 测试签名生成
func TestSignatureSDK_GenerateSign(t *testing.T) {
	// 创建mock数据库
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	sdk := NewSignatureSDK(&Config{DB: db})

	// 模拟数据库查询返回
	rows := sqlmock.NewRows([]string{"id", "app_id", "secret_key", "ips_white", "status", "create_at", "update_at"}).
		AddRow(1, "test_app", "secret123", `["192.168.1.1"]`, 1, 1640995200, nil)

	mock.ExpectQuery("SELECT (.+) FROM app_keys WHERE app_id = (.+)").
		WithArgs("test_app").
		WillReturnRows(rows)

	// 测试数据
	params := &SignParams{
		AppID:     "test_app",
		Timestamp: 1640995200,
		Nonce:     "abc123",
		Data: map[string]string{
			"user_id": "12345",
			"action":  "login",
		},
	}

	// 生成签名
	signature, err := sdk.GenerateSign(params)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	// 验证所有预期的数据库调用都已执行
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSignatureSDK_VerifySign 测试签名验证
func TestSignatureSDK_VerifySign(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	sdk := NewSignatureSDK(&Config{DB: db})

	// 模拟数据库查询返回
	rows := sqlmock.NewRows([]string{"id", "app_id", "secret_key", "ips_white", "status", "create_at", "update_at"}).
		AddRow(1, "test_app", "secret123", `["192.168.1.1"]`, 1, 1640995200, nil)

	mock.ExpectQuery("SELECT (.+) FROM app_keys WHERE app_id = (.+)").
		WithArgs("test_app").
		WillReturnRows(rows)

	// 首先生成一个有效的签名
	timestamp := time.Now().Unix()
	data := map[string]string{
		"user_id": "12345",
		"action":  "login",
	}

	// 手动计算预期签名
	expectedSign := sdk.buildSignString(data, timestamp, "abc123", "secret123")
	expectedSignMD5 := sdk.md5Hash(expectedSign)

	// 验证签名
	verifyParams := &VerifyParams{
		AppID:     "test_app",
		Timestamp: timestamp,
		Nonce:     "abc123",
		Sign:      expectedSignMD5,
		Data:      data,
		ClientIP:  "192.168.1.1",
	}

	err = sdk.VerifySign(verifyParams)
	assert.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSignatureSDK_VerifySign_IPNotAllowed 测试IP不在白名单的情况
func TestSignatureSDK_VerifySign_IPNotAllowed(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	sdk := NewSignatureSDK(&Config{DB: db})

	// 模拟数据库查询返回
	rows := sqlmock.NewRows([]string{"id", "app_id", "secret_key", "ips_white", "status", "create_at", "update_at"}).
		AddRow(1, "test_app", "secret123", `["192.168.1.1"]`, 1, 1640995200, nil)

	mock.ExpectQuery("SELECT (.+) FROM app_keys WHERE app_id = (.+)").
		WithArgs("test_app").
		WillReturnRows(rows)

	verifyParams := &VerifyParams{
		AppID:     "test_app",
		Timestamp: time.Now().Unix(),
		Nonce:     "abc123",
		Sign:      "dummy_sign",
		Data:      map[string]string{"test": "data"},
		ClientIP:  "192.168.1.100", // 不在白名单中的IP
	}

	err = sdk.VerifySign(verifyParams)
	assert.Equal(t, ErrIPNotAllowed, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// 实际使用示例
func ExampleRealWorldUsage() {
	// 1. 初始化数据库连接 (实际项目中替换为真实的数据库连接)
	db, err := sql.Open("postgres", "host=localhost user=myuser dbname=mydb sslmode=disable")
	if err != nil {
		fmt.Printf("数据库连接失败: %v\n", err)
		return
	}
	defer db.Close()

	// 2. 创建SDK实例
	sdk := NewSignatureSDK(&Config{DB: db})

	// 3. 服务端生成签名示例
	fmt.Println("=== 服务端生成签名 ===")

	signParams := &SignParams{
		AppID:     "my_app_001",
		Timestamp: time.Now().Unix(),
		Nonce:     generateNonce(), // 实际项目中应该生成随机字符串
		Data: map[string]string{
			"user_id":   "12345",
			"action":    "get_user_info",
			"version":   "1.0",
			"device_id": "abc123def456",
		},
	}

	signature, err := sdk.GenerateSign(signParams)
	if err != nil {
		fmt.Printf("生成签名失败: %v\n", err)
		return
	}

	fmt.Printf("应用ID: %s\n", signParams.AppID)
	fmt.Printf("时间戳: %d\n", signParams.Timestamp)
	fmt.Printf("随机数: %s\n", signParams.Nonce)
	fmt.Printf("业务数据: %+v\n", signParams.Data)
	fmt.Printf("生成的签名: %s\n", signature)

	// 4. 客户端验证签名示例
	fmt.Println("\n=== 客户端验证签名 ===")

	verifyParams := &VerifyParams{
		AppID:     signParams.AppID,
		Timestamp: signParams.Timestamp,
		Nonce:     signParams.Nonce,
		Sign:      signature,
		Data:      signParams.Data,
		ClientIP:  "192.168.1.10", // 客户端IP
	}

	err = sdk.VerifySign(verifyParams)
	if err != nil {
		fmt.Printf("签名验证失败: %v\n", err)
		return
	}

	fmt.Println("签名验证成功!")

	// 5. 应用管理示例
	fmt.Println("\n=== 应用管理示例 ===")

	// 创建新应用
	err = sdk.CreateAppKey("new_app_002", "new_secret_key_456", []string{
		"192.168.1.0/24", // 支持CIDR格式
		"10.0.0.1",       // 支持单个IP
	})
	if err != nil {
		fmt.Printf("创建应用失败: %v\n", err)
	} else {
		fmt.Println("应用创建成功!")
	}

	// 更新应用
	err = sdk.UpdateAppKey("new_app_002", "updated_secret_key", []string{
		"172.16.0.0/16",
	}, 1)
	if err != nil {
		fmt.Printf("更新应用失败: %v\n", err)
	} else {
		fmt.Println("应用更新成功!")
	}
}

// 生成随机字符串作为nonce
func generateNonce() string {
	return fmt.Sprintf("nonce_%d", time.Now().UnixNano())
}

// HTTPMiddleware HTTP中间件示例
func HTTPMiddleware(sdk *SignatureSDK) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 从请求中获取签名参数
			appID := r.Header.Get("X-App-ID")
			timestamp := r.Header.Get("X-Timestamp")
			nonce := r.Header.Get("X-Nonce")
			sign := r.Header.Get("X-Sign")

			if appID == "" || timestamp == "" || nonce == "" || sign == "" {
				http.Error(w, "缺少必要的签名参数", http.StatusBadRequest)
				return
			}

			// 解析时间戳
			ts, err := strconv.ParseInt(timestamp, 10, 64)
			if err != nil {
				http.Error(w, "时间戳格式错误", http.StatusBadRequest)
				return
			}

			// 获取请求参数
			data := make(map[string]string)
			for key, values := range r.URL.Query() {
				if len(values) > 0 {
					data[key] = values[0]
				}
			}

			// 获取客户端IP
			clientIP := getClientIP(r)

			// 验证签名
			verifyParams := &VerifyParams{
				AppID:     appID,
				Timestamp: ts,
				Nonce:     nonce,
				Sign:      sign,
				Data:      data,
				ClientIP:  clientIP,
			}

			if err := sdk.VerifySign(verifyParams); err != nil {
				http.Error(w, fmt.Sprintf("签名验证失败: %v", err), http.StatusUnauthorized)
				return
			}

			// 签名验证通过，继续处理请求
			next.ServeHTTP(w, r)
		})
	}
}

// 获取客户端真实IP
func getClientIP(r *http.Request) string {
	// 首先检查X-Forwarded-For头
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// 检查X-Real-IP头
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// 最后使用RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// Gin框架中间件示例
func GinMiddleware(sdk *SignatureSDK) gin.HandlerFunc {
	return func(c *gin.Context) {
		appID := c.GetHeader("X-App-ID")
		timestamp := c.GetHeader("X-Timestamp")
		nonce := c.GetHeader("X-Nonce")
		sign := c.GetHeader("X-Sign")

		if appID == "" || timestamp == "" || nonce == "" || sign == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "缺少必要的签名参数"})
			c.Abort()
			return
		}

		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "时间戳格式错误"})
			c.Abort()
			return
		}

		// 获取所有查询参数
		data := make(map[string]string)
		for key, values := range c.Request.URL.Query() {
			if len(values) > 0 {
				data[key] = values[0]
			}
		}

		verifyParams := &VerifyParams{
			AppID:     appID,
			Timestamp: ts,
			Nonce:     nonce,
			Sign:      sign,
			Data:      data,
			ClientIP:  c.ClientIP(),
		}

		if err := sdk.VerifySign(verifyParams); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("签名验证失败: %v", err)})
			c.Abort()
			return
		}

		c.Next()
	}
}
