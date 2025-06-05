package main

import (
	"database/sql"
	"fmt"
	"github.com/sulirlinc/go-signature-sdk"
	"log"
	"time"

	_ "github.com/lib/pq"
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
	err = sdk.CreateAppKey("test_app", "my_secret_key", []string{"127.0.0.1"})
	if err != nil {
		log.Println("创建应用密钥失败:", err)
	}

	// 生成签名
	params := &go_signature_sdk.SignParams{
		AppID:     "test_app",
		Timestamp: time.Now().Unix(),
		Nonce:     "random123",
		Data: map[string]string{
			"user_id": "12345",
			"action":  "login",
		},
	}

	sign, err := sdk.GenerateSign(params)
	if err != nil {
		log.Fatal("生成签名失败:", err)
	}

	fmt.Printf("生成的签名: %s\n", sign)

	// 验证签名
	verifyParams := &go_signature_sdk.VerifyParams{
		AppID:     params.AppID,
		Timestamp: params.Timestamp,
		Nonce:     params.Nonce,
		Sign:      sign,
		Data:      params.Data,
		ClientIP:  "127.0.0.1",
	}

	err = sdk.VerifySign(verifyParams)
	if err != nil {
		log.Fatal("签名验证失败:", err)
	}

	fmt.Println("签名验证成功!")
}
