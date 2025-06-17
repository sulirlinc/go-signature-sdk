package go_signature_sdk

import (
	"fmt"
	"net"
	"strings"
)

// verifyIPWhitelist 验证IP白名单
func (s *SignatureSDK) verifyIPWhitelist(clientIP string, whitelist []string) error {
	if len(whitelist) == 0 {
		return nil // 如果白名单为空，则不限制
	}

	clientIPAddr := net.ParseIP(clientIP)
	if clientIPAddr == nil {
		return fmt.Errorf("无效的客户端IP: %s", clientIP)
	}

	for _, whiteIP := range whitelist {
		// 支持单个IP和CIDR格式
		if strings.Contains(whiteIP, "/") {
			// CIDR格式
			_, ipNet, err := net.ParseCIDR(whiteIP)
			if err != nil {
				continue
			}
			if ipNet.Contains(clientIPAddr) {
				return nil
			}
		} else {
			// 单个IP
			if whiteIP == clientIP {
				return nil
			}
		}
	}

	return ErrIPNotAllowed
}
