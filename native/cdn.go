package native

import (
	"strings"
)

// 不用完整域名匹配（如 "webapp-prime.tiktok.com"）：TikTok 按地区下发的
// host 会插入地区段（如 v16-webapp-prime.us.tiktok.com），完整域名匹配不上；
// 用不含地区后缀的关键片段匹配才稳。
var gatedCDNMarkers = []string{"webapp-prime", "web-newkey"}

const PlayAPIMarker = "aweme/v1/play"

func IsGatedCDN(rawURL string) bool {
	for _, m := range gatedCDNMarkers {
		if strings.Contains(rawURL, m) {
			return true
		}
	}
	return false
}

// IsOpenCDN 判断该地址浏览器是否能直接下载，不需要 tt_chain_token Cookie。
// 需要走服务端代理的有两类：Play API（aweme/v1/play，依赖内部签名/Referer/
// Cookie）和 gated CDN（webapp-prime/web-newkey 等，实测裸取会 403，需要
// tt_chain_token）。其余（tiktokcdn.com、tiktokv.com、muscdn.com 及其地区
// 变体）视为可直接下载。
func IsOpenCDN(rawURL string) bool {
	return !IsPlayAPIURL(rawURL) && !IsGatedCDN(rawURL)
}

func IsPlayAPIURL(rawURL string) bool {
	return strings.Contains(rawURL, PlayAPIMarker)
}

// CDNRank returns a preference score for selecting among multiple CDN URLs.
// tiktokv.com = 2 (mobile native CDN, no cookie required)
// tiktokcdn.com / muscdn.com = 1 (open web CDN)
// others = 0
func CDNRank(rawURL string) int {
	if strings.Contains(rawURL, "tiktokv.com") {
		return 2
	}
	if strings.Contains(rawURL, "tiktokcdn") || strings.Contains(rawURL, "muscdn.com") {
		return 1
	}
	return 0
}
