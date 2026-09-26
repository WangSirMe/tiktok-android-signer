package native

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/WangSirMe/tiktok-android-signer/config"
	"github.com/WangSirMe/tiktok-android-signer/proxyctx"
)

var (
	httpClientMu sync.Mutex
	httpClients  = map[proxyctx.Profile]*http.Client{}
)

const directRequestTimeout = 3 * time.Second

// HTTPClientForContext 按 proxy 策略复用连接池（direct / configured）。
// profile 现在是进程级固定值（取决于 .env 是否配置 TIKTOK_PROXY_URL），
// ctx 仅用于兼容既有调用方，不再参与 profile 判断。
func HTTPClientForContext(ctx context.Context) *http.Client {
	profile := proxyctx.CurrentProfile()
	httpClientMu.Lock()
	defer httpClientMu.Unlock()
	if c, ok := httpClients[profile]; ok {
		return c
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 30
	transport.IdleConnTimeout = 90 * time.Second
	transport.Proxy = proxyctx.ProxyFuncForProfile(profile)
	c := &http.Client{
		Timeout:   RequestTimeoutForProfile(profile),
		Transport: transport,
	}
	httpClients[profile] = c
	return c
}

func RequestTimeout() time.Duration {
	return time.Duration(config.TikTok.RequestTimeout * float64(time.Second))
}

func RequestTimeoutForProfile(profile proxyctx.Profile) time.Duration {
	if profile == proxyctx.ProfileDirect {
		return directRequestTimeout
	}
	return RequestTimeout()
}
