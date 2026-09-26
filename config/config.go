package config

import (
	"os"
	"strconv"
	"strings"
)

// TikTokSettings 只保留 native 签名路径用到的两项;完整服务配置在原服务仓库里
type TikTokSettings struct {
	RequestTimeout float64 //请求超时,秒
	ProxyURL       string  //出站代理,留空直连
}

var TikTok TikTokSettings

func init() {
	TikTok.RequestTimeout = getenvFloat("TIKTOK_REQUEST_TIMEOUT", 15)
	TikTok.ProxyURL = getenv("TIKTOK_PROXY_URL", "")
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func getenvFloat(key string, def float64) float64 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}
