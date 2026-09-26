package proxyctx

import (
	"testing"

	"github.com/WangSirMe/tiktok-android-signer/config"
)

func TestEffectiveProxyURL(t *testing.T) {
	orig := config.TikTok.ProxyURL
	t.Cleanup(func() {
		config.TikTok.ProxyURL = orig
	})

	config.TikTok.ProxyURL = "http://127.0.0.1:7897"
	if got := EffectiveProxyURL(); got != "http://127.0.0.1:7897" {
		t.Fatalf("configured: want proxy url, got %q", got)
	}

	config.TikTok.ProxyURL = ""
	if got := EffectiveProxyURL(); got != "" {
		t.Fatalf("unconfigured: want empty (direct), got %q", got)
	}
}

func TestCurrentProfile(t *testing.T) {
	orig := config.TikTok.ProxyURL
	t.Cleanup(func() {
		config.TikTok.ProxyURL = orig
	})

	config.TikTok.ProxyURL = "http://127.0.0.1:7897"
	if CurrentProfile() != ProfileConfigured {
		t.Fatal("expected configured profile when TIKTOK_PROXY_URL is set")
	}

	config.TikTok.ProxyURL = ""
	if CurrentProfile() != ProfileDirect {
		t.Fatal("expected direct profile when TIKTOK_PROXY_URL is unset")
	}
}
