package go_signature_sdk

import (
	"fmt"
	"testing"
)

func TestSignatureSDK_GenerateSign(t *testing.T) {
	// 测试数据 - 包含嵌套结构
	data := map[string]interface{}{
		"appid": map[string]interface{}{
			"a": "1",
			"b": map[string]interface{}{
				"b1": "hello",
				"b2": "world",
			},
		},
		"mch_id":      "1000001",
		"nonce_str":   "abc123",
		"body":        "测试商品",
		"total_fee":   100,
		"trade_type":  "JSAPI",
		"empty_field": "",
	}

	secretKey := "your_secret_key"

	// 展开嵌套结构生成签名
	signString := GenerateSign(data, secretKey)
	fmt.Println("签名字符串:")
	fmt.Println(signString)
}
