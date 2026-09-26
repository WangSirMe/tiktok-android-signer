package native

import (
	"encoding/json"
	"fmt"

	"github.com/WangSirMe/tiktok-android-signer/parseerr"
)

var statusMap = map[int]*parseerr.ParserError{
	10202: parseerr.ErrNotFound,
	10203: parseerr.ErrPrivate,
	10204: parseerr.ErrNotFound,
	10205: parseerr.ErrPrivate,
	10216: parseerr.ErrPrivate,
	10217: parseerr.ErrNotFound,
	10218: parseerr.ErrUnsupported,
	10219: parseerr.ErrUnsupported,
	// native multi/aweme/detail 的「视频在当前上下文不可用」(status_msg:
	// "unavailable video default"):视频不存在/已删除/对匿名区域设备不可见,
	// 同一视频网页路径通常报 10204(ErrNotFound),这里对齐语义。
	3020004: parseerr.ErrNotFound,
}

func ParseItemDetailResponse(data map[string]any, fallbackID string) (*RawItemDetail, error) {
	if sc, ok := data["statusCode"].(float64); ok && int(sc) != 0 {
		msg, _ := data["statusMsg"].(string)
		if msg == "" {
			msg, _ = data["message"].(string)
		}
		return nil, raiseForStatus(int(sc), msg)
	}
	// Native app API (aweme/v1/item/detail/) uses snake_case status fields.
	if sc, ok := data["status_code"].(float64); ok && int(sc) != 0 {
		msg, _ := data["status_msg"].(string)
		if msg == "" {
			msg, _ = data["message"].(string)
		}
		return nil, raiseForStatus(int(sc), msg)
	}

	itemStruct := extractItemStruct(data)
	if itemStruct == nil {
		return nil, parseerr.UpstreamError("Video data not found in API response.")
	}

	var ttChain *string
	if v, ok := data["tt_chain_token"].(string); ok && v != "" {
		ttChain = &v
	} else if v, ok := data["ttChainToken"].(string); ok && v != "" {
		ttChain = &v
	}

	return itemStructToRaw(itemStruct, fallbackID, ttChain)
}

func raiseForStatus(code int, msg string) error {
	if exc, ok := statusMap[code]; ok {
		return exc
	}
	if msg == "" {
		msg = fmt.Sprintf("TikTok API returned status %d", code)
	}
	return parseerr.UpstreamError(msg)
}

// ---- JSON 宽容取值辅助(源自已删除的 v1 embed 路径,response.go 继续使用) ----

// pickCover 从全部封面变体(cover/origin_cover/dynamic_cover,兼容
// camelCase)收集 URL,优先浏览器可直接渲染的格式(jpeg/webp/png)——
// Chromium 系 <img> 不支持 HEIC,photomode 视频的 cover 常是 heic,
// 而 origin_cover 等变体往往是 jpeg/webp。
func pickCover(video map[string]any) string {
	candidates := firstURLList(
		video["cover"], video["origin_cover"], video["originCover"],
		video["dynamic_cover"], video["dynamicCover"],
	)
	if len(candidates) == 0 {
		return ""
	}
	for _, u := range candidates {
		if isBrowserFriendlyImage(u) {
			return u
		}
	}
	return candidates[0]
}

func isBrowserFriendlyImage(rawURL string) bool {
	i := stringsIndexByte(rawURL, '?')
	p := rawURL
	if i >= 0 {
		p = rawURL[:i]
	}
	lower := stringsToLower(p)
	// .awebp(动图 webp)现代浏览器 <img> 均可渲染
	for _, ext := range []string{".jpeg", ".jpg", ".webp", ".awebp", ".png"} {
		if stringsHasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func firstURLList(values ...any) []string {
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if stringsHasPrefix(t, "http") {
				out = append(out, t)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			walk(t["urlList"])
			walk(t["url_list"])
			walk(t["UrlList"])
		}
	}
	for _, v := range values {
		walk(v)
	}
	return out
}

func firstURL(values ...any) string {
	for _, v := range values {
		switch t := v.(type) {
		case string:
			if stringsHasPrefix(t, "http") {
				return t
			}
		case []any:
			if u := firstURL(t...); u != "" {
				return u
			}
		case map[string]any:
			if u := firstURL(t["urlList"], t["url_list"], t["UrlList"]); u != "" {
				return u
			}
			if uri, ok := t["uri"].(string); ok && stringsHasPrefix(uri, "http") {
				return uri
			}
		}
	}
	return ""
}

func toInt(values ...any) *int {
	for _, v := range values {
		switch t := v.(type) {
		case float64:
			n := int(t)
			return &n
		case json.Number:
			if n, err := t.Int64(); err == nil {
				i := int(n)
				return &i
			}
		case string:
			var n int
			if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
				return &n
			}
		}
	}
	return nil
}

func strField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok {
			return v
		}
		if v, ok := m[k].(float64); ok {
			return fmt.Sprintf("%.0f", v)
		}
	}
	return ""
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func stringsIndexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func stringsToLower(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

func sliceStr(values ...any) []string {
	for _, v := range values {
		switch t := v.(type) {
		case []any:
			out := make([]string, 0, len(t))
			for _, item := range t {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
			return out
		case []string:
			return t
		}
	}
	return nil
}

func extractItemStruct(data map[string]any) map[string]any {
	if itemInfo, ok := data["itemInfo"].(map[string]any); ok {
		if struct_, ok := itemInfo["itemStruct"].(map[string]any); ok {
			return struct_
		}
	}
	if struct_, ok := data["itemStruct"].(map[string]any); ok {
		return struct_
	}
	if aweme, ok := data["aweme_detail"].(map[string]any); ok {
		return aweme
	}
	if aweme, ok := data["awemeDetail"].(map[string]any); ok {
		return aweme
	}
	// multi/aweme/detail returns a list under aweme_details.
	if list, ok := data["aweme_details"].([]any); ok && len(list) > 0 {
		if aweme, ok := list[0].(map[string]any); ok {
			return aweme
		}
	}
	return nil
}

func itemStructToRaw(item map[string]any, fallbackID string, ttChain *string) (*RawItemDetail, error) {
	if status, ok := item["status"].(map[string]any); ok {
		if priv, ok := status["isPrivate"].(bool); ok && priv {
			return nil, parseerr.ErrPrivate
		}
	}
	if item["imagePost"] != nil || item["images"] != nil {
		return nil, parseerr.ErrUnsupported
	}

	authorRaw, _ := item["author"].(map[string]any)
	statsRaw, _ := item["stats"].(map[string]any)
	if statsRaw == nil {
		// native app API(aweme_detail)的统计在 statistics(snake_case);
		// webpage/embed 路径用 stats(camelCase)。
		statsRaw, _ = item["statistics"].(map[string]any)
	}
	videoRaw, _ := item["video"].(map[string]any)
	musicRaw, _ := item["music"].(map[string]any)
	if musicRaw == nil {
		musicRaw, _ = item["added_sound_music_info"].(map[string]any)
	}

	medias := extractMedias(videoRaw, musicRaw)

	id := fallbackID
	if v, ok := item["id"].(string); ok && v != "" {
		id = v
	} else if v, ok := item["id"].(float64); ok {
		id = fmt.Sprintf("%.0f", v)
	} else if v, ok := item["aweme_id"].(string); ok && v != "" {
		id = v
	}

	desc, _ := item["desc"].(string)
	if desc == "" {
		desc, _ = item["title"].(string)
	}

	var author RawAuthor
	if authorRaw != nil {
		author.UniqueID = strField(authorRaw, "uniqueId", "unique_id")
		author.Nickname = strField(authorRaw, "nickname")
		author.ID = strField(authorRaw, "id", "uid")
	}

	cover := pickCover(videoRaw)
	var coverPtr *string
	if cover != "" {
		coverPtr = &cover
	}

	var stats *RawStats
	if statsRaw != nil {
		stats = &RawStats{
			PlayCount: toInt(statsRaw["playCount"], statsRaw["play_count"]),
			DiggCount: toInt(statsRaw["diggCount"], statsRaw["digg_count"]),
		}
	}

	duration := toInt(videoRaw["duration"])

	return &RawItemDetail{
		ID:           id,
		Desc:         desc,
		Author:       author,
		CoverURL:     coverPtr,
		Duration:     duration,
		Stats:        stats,
		Medias:       medias,
		TTChainToken: ttChain,
	}, nil
}

func extractMedias(video, music map[string]any) []RawMedia {
	var medias []RawMedia
	if video == nil {
		video = map[string]any{}
	}
	defaultW := toInt(video["width"])
	defaultH := toInt(video["height"])

	seenURLs := map[string]struct{}{}

	// bitrateInfo: one entry per quality, pick the best open CDN URL from each
	for _, br := range sliceAny(video["bitrateInfo"], video["bitrate_info"], video["bit_rate"]) {
		brMap, ok := br.(map[string]any)
		if !ok {
			continue
		}
		codec := strField(brMap, "CodecType", "codec_type")
		po := firstMap(brMap["PlayAddr"], brMap["play_addr"])
		brRate := toInt(brMap["Bitrate"], brMap["bitrate"])
		w := coalesceInt(toInt(brMap["Width"], brMap["width"]), defaultW)
		h := coalesceInt(toInt(brMap["Height"], brMap["height"]), defaultH)
		appendSingleMedia(&medias, seenURLs, po, w, h, brRate, codec)
	}

	// download_addr only as fallback when bitrateInfo produced no video entries
	if countVideoMedias(medias) == 0 {
		downloadObj := firstMap(video["downloadAddr"], video["download_addr"])
		appendSingleMedia(&medias, seenURLs, downloadObj, defaultW, defaultH, nil, "")
	}

	if music != nil {
		if mu := firstURL(music["playUrl"], music["play_url"]); mu != "" {
			medias = append(medias, RawMedia{PlayURL: mu, IsAudio: true})
		}
	}
	return medias
}

// appendSingleMedia picks the single best open CDN URL from playObj (or falls back to any URL)
// and appends one RawMedia entry. Uses seenURLs to deduplicate across entries.
func appendSingleMedia(medias *[]RawMedia, seen map[string]struct{}, playObj any, width, height, bitrate *int, codec string) {
	if playObj == nil {
		return
	}
	w, h, sz := playAddrFields(playObj)
	outW := coalesceInt(w, width)
	outH := coalesceInt(h, height)

	rawURL := bestOpenCDNURL(playObj)
	if rawURL == "" {
		rawURL = pickPlayURL(playObj)
	}
	if rawURL == "" {
		return
	}
	if _, ok := seen[rawURL]; ok {
		return
	}
	seen[rawURL] = struct{}{}
	*medias = append(*medias, RawMedia{
		PlayURL:   rawURL,
		Width:     outW,
		Height:    outH,
		SizeBytes: sz,
		Bitrate:   bitrate,
		Codec:     codec,
	})
}

// bestOpenCDNURL picks the highest-ranked open CDN URL from a play object's urlList.
// Prefers tiktokv.com (mobile native CDN, rank 2) over tiktokcdn.com (rank 1).
func bestOpenCDNURL(value any) string {
	if s, ok := value.(string); ok && stringsHasPrefix(s, "http") && IsOpenCDN(s) {
		return s
	}
	m, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	best := ""
	bestRank := -1
	for _, u := range sliceStr(m["urlList"], m["url_list"], m["UrlList"]) {
		if !stringsHasPrefix(u, "http") || !IsOpenCDN(u) {
			continue
		}
		if r := CDNRank(u); r > bestRank {
			bestRank = r
			best = u
		}
	}
	return best
}

func countVideoMedias(medias []RawMedia) int {
	n := 0
	for _, m := range medias {
		if !m.IsAudio {
			n++
		}
	}
	return n
}

func pickPlayURL(value any) string {
	if s, ok := value.(string); ok && stringsHasPrefix(s, "http") {
		return s
	}
	m, ok := value.(map[string]any)
	if !ok {
		return firstURL(value)
	}
	urls := sliceStr(m["urlList"], m["url_list"], m["UrlList"])
	for _, c := range urls {
		if stringsHasPrefix(c, "http") && IsOpenCDN(c) {
			return c
		}
	}
	for _, c := range urls {
		if stringsContains(c, "aweme/v1/play") {
			return c
		}
	}
	for _, c := range urls {
		if stringsHasPrefix(c, "http") && !stringsContains(c, "webapp-prime.tiktok.com") {
			return c
		}
	}
	if len(urls) > 0 {
		return urls[0]
	}
	if uri, ok := m["uri"].(string); ok && stringsHasPrefix(uri, "http") {
		return uri
	}
	return ""
}

func playAddrFields(playObj any) (*int, *int, *int) {
	m, ok := playObj.(map[string]any)
	if !ok {
		return nil, nil, dataSize(playObj)
	}
	return toInt(m["Width"], m["width"]), toInt(m["Height"], m["height"]),
		toInt(m["DataSize"], m["data_size"])
}

func dataSize(v any) *int {
	if m, ok := v.(map[string]any); ok {
		return toInt(m["data_size"], m["dataSize"])
	}
	return nil
}

func firstMap(values ...any) any {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

func sliceAny(values ...any) []any {
	for _, v := range values {
		if s, ok := v.([]any); ok {
			return s
		}
	}
	return nil
}

func coalesceInt(a, b *int) *int {
	if a != nil {
		return a
	}
	return b
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
