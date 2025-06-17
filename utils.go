package go_signature_sdk

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// md5Hash 生成MD5哈希
func md5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// flattenMap 递归展开嵌套的map
func flattenMap(data interface{}, prefix string, result map[string]string) {
	switch v := data.(type) {
	case map[string]interface{}:
		for k, val := range v {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenMap(val, key, result)
		}
	case []interface{}:
		for i, val := range v {
			key := fmt.Sprintf("%s[%d]", prefix, i)
			flattenMap(val, key, result)
		}
	default:
		if v != nil {
			result[prefix] = fmt.Sprintf("%v", v)
		}
	}
}

// buildSignString 构建签名字符串
func buildSignString(data map[string]interface{}, secretKey string) string {
	// 展开所有嵌套参数
	allParams := make(map[string]string)

	for k, v := range data {
		if v == nil {
			continue
		}

		// 如果是嵌套结构，递归展开
		switch val := v.(type) {
		case map[string]interface{}:
			flattenMap(val, k, allParams)
		case []interface{}:
			flattenMap(val, k, allParams)
		default:
			// 简单值直接转换
			strVal := fmt.Sprintf("%v", val)
			if strVal != "" {
				allParams[k] = strVal
			}
		}
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
