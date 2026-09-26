package native

import "github.com/WangSirMe/tiktok-android-signer/models"

// ParseAlgVersion 内部算法版标识(原 version=3,现统一为 2)。parse_cache 的
// 缓存 key 前缀用它隔离不同解析算法的缓存条目。
const ParseAlgVersion = 2

type RawAuthor struct {
	UniqueID string
	Nickname string
	ID       string
}

type RawStats struct {
	PlayCount *int
	DiggCount *int
}

type RawMedia struct {
	PlayURL       string
	Width         *int
	Height        *int
	Bitrate       *int
	SizeBytes     *int
	IsWatermarked bool
	IsAudio       bool
	Codec         string // "h264", "h265", "bytevc1", "bytevc2", "" (unknown)
}

type RawItemDetail struct {
	ID           string
	Desc         string
	Author       RawAuthor
	CoverURL     *string
	Duration     *int
	Stats        *RawStats
	Medias       []RawMedia
	TTChainToken *string
	// Sign 是 v2 native 路径的签名产物(detail URL + 4 件套),仅 native 路径填充。
	Sign *models.SignArtifact
}
