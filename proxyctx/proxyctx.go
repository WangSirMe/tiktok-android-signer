package proxyctx

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/WangSirMe/tiktok-android-signer/config"
)

func configuredProxyURL() string {
	return strings.TrimSpace(config.TikTok.ProxyURL)
}

// EffectiveProxyURL 返回当前应使用的代理地址：.env 里配置了 TIKTOK_PROXY_URL
// 就用它，否则走本地网络直连。全进程统一，不支持按请求切换。
func EffectiveProxyURL() string {
	return configuredProxyURL()
}

type Profile string

const (
	ProfileDirect     Profile = "direct"
	ProfileConfigured Profile = "configured"
)

// CurrentProfile 根据 .env 是否配置了 TIKTOK_PROXY_URL 决定当前 profile，
// 全进程统一，不再支持按请求切换。
func CurrentProfile() Profile {
	if configuredProxyURL() != "" {
		return ProfileConfigured
	}
	return ProfileDirect
}

func ProxyFuncForProfile(profile Profile) func(*http.Request) (*url.URL, error) {
	if profile == ProfileConfigured {
		if p := configuredProxyURL(); p != "" {
			if u, err := url.Parse(p); err == nil {
				return http.ProxyURL(u)
			}
		}
	}
	return func(*http.Request) (*url.URL, error) { return nil, nil }
}

func TLSProxyURLForProfile(profile Profile) string {
	if profile == ProfileConfigured {
		return configuredProxyURL()
	}
	return ""
}
