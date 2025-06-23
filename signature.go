package go_signature_sdk

import (
	"log"
	"strings"
)

// GenerateSign 生成签名
func GenerateSign(data map[string]interface{}, secretKey string) (string, string) {
	signStr := buildSignString(data, secretKey)
	return md5Hash(signStr), strings.ReplaceAll(signStr, secretKey, "***SECRET***")
}

// VerifySign 验证签名
func VerifySign(params *VerifyParams, secretKey string) error {
	sign := params.Data["sign"]
	params.Data["sign"] = ""
	generateSign, s := GenerateSign(params.Data, secretKey)
	if generateSign != sign {
		log.Println("签名验证失败:", generateSign, s)
		return ErrInvalidSign
	}
	return nil
}
