package go_signature_sdk

// GenerateSign 生成签名
func GenerateSign(data map[string]interface{}, secretKey string) string {
	signStr := buildSignString(data, secretKey)
	return md5Hash(signStr)
}

// VerifySign 验证签名
func VerifySign(params *VerifyParams, secretKey string) error {
	sign := params.Data["sign"]
	params.Data["sign"] = ""
	if GenerateSign(params.Data, secretKey) != sign {
		return ErrInvalidSign
	}
	return nil
}
