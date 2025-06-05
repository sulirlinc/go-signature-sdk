# MD5签名验签SDK

一个基于Go语言的MD5签名验签SDK，支持数据库存储、IP白名单验证等功能。

## 特性

- ✅ MD5签名生成和验证
- ✅ 参数按ASCII码排序
- ✅ PostgreSQL数据库支持
- ✅ IP白名单验证（支持单IP和CIDR格式）
- ✅ 时间戳验证（防重放攻击）
- ✅ 应用密钥管理
- ✅ HTTP/Gin中间件支持
- ✅ 完整的单元测试

## 安装

```bash
go get github.com/sulirlinc/go-signature-sdk
```

## 依赖

```go
// go.mod
module signature-sdk

go 1.19

require (
github.com/lib/pq v1.10.9
github.com/DATA-DOG/go-sqlmock v1.5.0
github.com/stretchr/testify v1.8.4
github.com/gin-gonic/gin v1.9.1
)
```

## 数据库表结构

```sql
CREATE TABLE app_keys (
  id SERIAL PRIMARY KEY,
  app_id VARCHAR(32) NOT NULL UNIQUE,
  secret_key VARCHAR(64) NOT NULL,
  ips_white JSONB NOT NULL,
  status SMALLINT NOT NULL DEFAULT 1,
  create_at BIGINT NOT NULL,
  update_at BIGINT DEFAULT NULL
);

CREATE INDEX idx_app_keys_app_id ON app_keys(app_id);
CREATE INDEX idx_app_keys_status ON app_keys(status);

COMMENT ON TABLE app_keys IS '应用密钥表';
COMMENT ON COLUMN app_keys.app_id IS '应用ID';
COMMENT ON COLUMN app_keys.secret_key IS '密钥';
COMMENT ON COLUMN app_keys.ips_white IS 'ip白名单';
COMMENT ON COLUMN app_keys.status IS '状态 1:启用 0:禁用';
COMMENT ON COLUMN app_keys.create_at IS '创建时间戳';
COMMENT ON COLUMN app_keys.update_at IS '更新时间戳';
```

## 快速开始

### 1. 初始化SDK

```go
package main

import (
    "database/sql"
    "signature"
    _ "github.com/lib/pq"
)

func main() {
    // 连接数据库
    db, err := sql.Open("postgres", "user=username dbname=mydb sslmode=disable")
    if err != nil {
        panic(err)
    }
    defer db.Close()
    
    // 创建SDK实例
    sdk := signature.NewSignatureSDK(&signature.Config{DB: db})
}
```

### 2. 创建应用

```go
// 创建应用密钥
err = sdk.CreateAppKey("my_app", "my_secret_key", []string{
    "192.168.1.1",     // 单个IP
    "10.0.0.0/8",      // CIDR格式
})
if err != nil {
    panic(err)
}
```

### 3. 生成签名

```go
// 构建签名参数
signParams := &signature.SignParams{
    AppID:     "my_app",
    Timestamp: time.Now().Unix(),
    Nonce:     "random_nonce_123",
    Data: map[string]string{
        "user_id": "12345",
        "action":  "login",
        "version": "1.0",
    },
}

// 生成签名
sign, err := sdk.GenerateSign(signParams)
if err != nil {
    panic(err)
}

fmt.Printf("生成的签名: %s\n", sign)
```

### 4. 验证签名

```go
// 验证签名参数
verifyParams := &signature.VerifyParams{
    AppID:     "my_app",
    Timestamp: signParams.Timestamp,
    Nonce:     signParams.Nonce,
    Sign:      sign,
    Data:      signParams.Data,
    ClientIP:  "192.168.1.1",
}

// 验证签名
err = sdk.VerifySign(verifyParams)
if err != nil {
    fmt.Printf("签名验证失败: %v\n", err)
    return
}

fmt.Println("签名验证成功!")
```

## 签名算法

### 签名生成流程

1. 将所有参数（包括业务参数、timestamp、nonce）按键名ASCII码排序
2. 构建签名字符串：`key1=value1&key2=value2&...&key=secret_key`
3. 对签名字符串进行MD5加密，转为大写

### 示例

假设有以下参数：
```
user_id: "12345"
action: "login"
timestamp: 1640995200
nonce: "abc123"
secret_key: "my_secret"
```

排序后的签名字符串：
```
action=login&nonce=abc123&timestamp=1640995200&user_id=12345&key=my_secret
```

MD5加密后的签名：
```
E8F7B8C2A1D3F4E5B6C7D8E9F0A1B2C3
```

## HTTP中间件使用

### 标准HTTP

```go
import (
    "net/http"
    "signature"
)

func main() {
    sdk := signature.NewSignatureSDK(&signature.Config{DB: db})
    
    // 创建HTTP处理器
    mux := http.NewServeMux()
    mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("用户信息"))
    })
    
    // 应用签名验证中间件
    handler := signature.HTTPMiddleware(sdk)(mux)
    
    http.ListenAndServe(":8080", handler)
}
```

### Gin框架

```go
import (
    "github.com/gin-gonic/gin"
    "signature"
)

func main() {
    sdk := signature.NewSignatureSDK(&signature.Config{DB: db})
    
    r := gin.Default()
    
    // 应用签名验证中间件
    r.Use(signature.GinMiddleware(sdk))
    
    r.GET("/api/user", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "用户信息"})
    })
    
    r.Run(":8080")
}
```

## 客户端请求示例

### HTTP请求头

```
X-App-ID: my_app
X-Timestamp: 1640995200
X-Nonce: abc123
X-Sign: E8F7B8C2A1D3F4E5B6C7D8E9F0A1B2C3
```

### cURL示例

```bash
curl -X GET "http://localhost:8080/api/user?user_id=12345&action=login" \
  -H "X-App-ID: my_app" \
  -H "X-Timestamp: 1640995200" \
  -H "X-Nonce: abc123" \
  -H "X-Sign: E8F7B8C2A1D3F4E5B6C7D8E9F0A1B2C3"
```

## 错误处理

SDK定义了以下错误类型：

```go
var (
    ErrAppNotFound    = errors.New("应用不存在")
    ErrAppDisabled    = errors.New("应用已禁用")
    ErrIPNotAllowed   = errors.New("IP不在白名单中")
    ErrInvalidSign    = errors.New("签名验证失败")
    ErrExpiredRequest = errors.New("请求已过期")
)
```

## 配置说明

### 时间戳验证

默认允许5分钟的时间误差，可以通过修改`verifyTimestamp`方法中的时间差来调整：

```go
// 允许5分钟的时间误差
if diff > 300 || diff < -300 {
return ErrExpiredRequest
}
```

### IP白名单格式

支持两种格式：
- 单个IP：`192.168.1.1`
- CIDR格式：`192.168.1.0/24`、`10.0.0.0/8`

## 安全建议

1. **密钥管理**：secret_key应该足够复杂，建议使用随机生成的64位字符串
2. **HTTPS传输**：生产环境中应该使用HTTPS协议传输
3. **nonce防重放**：可以将nonce存储到Redis中，防止重复使用
4. **时间戳验证**：根据业务需求调整时间戳的容错范围
5. **IP白名单**：严格控制允许访问的IP地址

## 单元测试

运行测试：

```bash
go test -v ./...
```

测试覆盖率：

```bash
go test -cover ./...
```

## 性能优化

1. **数据库连接池**：合理配置数据库连接池大小
2. **缓存密钥**：可以将应用密钥信息缓存到Redis中
3. **并发控制**：SDK是线程安全的，支持并发使用

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！