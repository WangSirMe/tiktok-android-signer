package models

type VideoStats struct {
	Plays *string `json:"plays,omitempty"`
	Likes *string `json:"likes,omitempty"`
}

type MediaFormat struct {
	Type      string  `json:"type"`
	SourceURL string  `json:"-"`
	Quality   string  `json:"quality,omitempty"`
	Ext       string  `json:"ext,omitempty"`
	Size      *string `json:"size,omitempty"`
	SizeBytes *int    `json:"-"`
	Width     *int    `json:"-"`
	Height    *int    `json:"-"`
	Bitrate   *int    `json:"-"`
	Codec     string  `json:"-"` // "h264", "h265", or "" (unknown/compatible)
}

type ParsedVideo struct {
	ID           string
	Title        string
	Author       string
	AuthorName   *string
	Thumbnail    *string
	Duration     *int
	Filename     string
	Stats        *VideoStats
	Formats      []MediaFormat
	TTChainToken *string
	// Sign 是 v2 native 路径附加的签名产物:离线签名的完整 detail URL + 4 件套
	// 签名头 + TikTok 原始响应。供探针/调试对拍,不透出到 API 响应。
	Sign *SignArtifact
}

// SignArtifact 是签名产物:签名输入的完整 URL + 请求 header + 4 件套签名头 +
// 用该签名实际请求 URL 的原始响应结果(result)。
type SignArtifact struct {
	URL      string       `json:"url"`     // 完整请求 URL(含 query,含 aweme_id=vid & iid=...)
	Headers  []SignHeader `json:"headers"` // 请求头数组(签名输入)
	XArgus   string       `json:"x_argus"`
	XGorgon  string       `json:"x_gorgon"`
	XKhronos string       `json:"x_khronos"`
	XLadon   string       `json:"x_ladon"`
	// Result 是用算出的 4 签实际请求 url(带 headers)后,TikTok 返回的原始响应体。
	// 签名被接受时是 detail JSON;被拒签时为空串。供调用方核对签名是否被接受。
	Result string `json:"result"`
	// Body 是 POST detail 请求的请求体(aweme_ids=[<vid>]&request_source=1)。
	// X-SS-STUB = MD5(Body)。供对拍:核对 stub 与 body 是否匹配。
	Body string `json:"body"`
	// Curl 是把签名后的完整请求(url + headers + body)封装成的 curl 命令,
	// 直接复制到终端即可重放,用于对拍/调试。仅 v2 native 路径填充。
	Curl string `json:"curl,omitempty"`
}

// SignHeader 是签名输入的一个请求头字段。
type SignHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
