package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/sulirlinc/go-signature-sdk"
	"log"
)

func main() {
	// 连接数据库
	db, err := sql.Open("postgres", "host=localhost user=postgres dbname=testdb sslmode=disable")
	if err != nil {
		log.Fatal("数据库连接失败:", err)
	}
	defer db.Close()

	// 创建SDK实例
	sdk := go_signature_sdk.NewSignatureSDK(&go_signature_sdk.Config{DB: db})

	// 创建应用密钥
	err = sdk.CreateAppKey("test_app", "my_secret_key", []string{"127.0.0.1"}, map[string]interface{}{"description": "测试应用"})
	if err != nil {
		log.Println("创建应用密钥失败:", err)
	}

	// 生成签名
	params := &go_signature_sdk.SignParams{
		AppID: "test_app",
		Data: map[string]interface{}{
			"user_id": "12345",
			"action":  "login",
		},
	}

	if err := sdk.GenerateSign(params); err != nil {
		log.Fatal("签名生成失败:", err)
	}

	fmt.Printf("生成的签名: %s\n", params.Data["sign"])

	// 验证签名
	verifyParams := &go_signature_sdk.VerifyParams{
		AppID:    params.AppID,
		Data:     params.Data,
		ClientIP: "127.0.0.1",
	}

	err = sdk.VerifySign(verifyParams)
	if err != nil {
		log.Fatal("签名验证失败:", err)
	}

	fmt.Println("签名验证成功!")
}
