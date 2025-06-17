package go_signature_sdk

import "errors"

// 错误定义
var (
	ErrAppNotFound    = errors.New("应用不存在")
	ErrAppDisabled    = errors.New("应用已禁用")
	ErrIPNotAllowed   = errors.New("IP不在白名单中")
	ErrInvalidSign    = errors.New("签名验证失败")
	ErrExpiredRequest = errors.New("请求已过期")
)
