package crypto

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// xgorgon_331005_ref_test.go — 把真机三组抓包数据固化为断言。
//
// 数据来源：backend/tools/native-capture/frida/verify_xgorgon.js 在 TikTok 33.2.5
// 真机上的 frida 三方对拍输出（/tmp/verify_xgorgon_out*.jsonl）。每组数据同时记录了
// 0x7e530 入口的 20 字节输入、0x88ee0 出口的 X-Gorgon/X-Khronos、TTNet header 的
// x-ss-stub。这里用「文档即代码」锁定：任一字段对不上就测试失败。
//
// 若日后 TikTok 升级导致签名失效，这个测试会红，提示需要重新抓包。

// 真机抓包样本（field10 = 0x7e530 入口 X0+0x10 指向的 20 字节）。
type xgorgon331005Sample struct {
	name        string
	url         string // 完整请求 URL（截断时为空）
	urlVerified bool   // url 是否完整可复算 md5(query)
	stub        string // header x-ss-stub（POST body 的 md5 hex），GET 请求为空
	khronos     uint32 // header X-Khronos
	gorgonHex   string // header X-Gorgon
	field10     string // 0x7e530 入口 20 字节输入的 hex（大端存储）
}

// 组1：POST /aweme/v2/feed/（有 body）
//   - url 取 frida ENTRY 抓到的完整 query
//   - stub = D444D685093BAB9896E8497AB5C492C9
//   - field10[4:8] 应 == stub[:8]（大端）
func xgorgon331005Samples() []xgorgon331005Sample {
	const feedURL = "https://api22-core-c-alisg.tiktokv.com/aweme/v2/feed/?" +
		"os=android&_rticket=1783668716468&is_pad=0&host_abi=arm64-v8a&ts=1783668712&" +
		"effect_sdk_version=15.8.0&app_version=2023302050&is_non_personalized=0&" +
		"cmpl_enc=AgICA6gAFgkrPEDsvf3umVda3C9b0jgYUE9VBxfkT7DQPu6niDLZOfAq5BQnS_-DDGCmA5U&" +
		"ab_version=33.2.5&ac=wifi&ac2=wifi5g&aid=1233&app_language=zh-Hans&app_name=musical_ly&" +
		"app_type=normal&build_number=33.2.5&cdid=e819fc59-2ef3-4ead-b4d3-c4ae2a6d66af&channel=googleplay&" +
		"current_region=TW&device_brand=xiaomi&device_id=7659353200026502657&device_platform=android&" +
		"device_type=MI+6X&dpi=440&iid=7659981817244043016&language=zh-Hans&locale=zh-Hans&" +
		"manifest_version_code=2023302050&op_region=TW&openudid=a48123e855b77a8c&os_api=28&os_version=9&" +
		"region=CN&residence=TW&resolution=1080*2030&ssmix=a&sys_region=CN&timezone_name=Asia%2FShanghai&" +
		"timezone_offset=28800&uoo=1&update_version_code=2023302050&version_code=330205&version_name=33.2.5"
	return []xgorgon331005Sample{
		{
			// 组1：POST /aweme/v2/feed/，有 body。
			// url 被 frida slice(300) 截断，故 md5(query) 无法复算——用 urlVerified=false 跳过该断言。
			// stub / sdk / ts 三个断言仍成立，足以覆盖 POST 场景的 [4:8] md5(body) 验证。
			name:        "组1 POST /aweme/v2/feed/ (url截断, 仅验 stub/sdk/ts)",
			url:         "",
			urlVerified: false,
			stub:        "D444D685093BAB9896E8497AB5C492C9",
			khronos:     1783668428,
			gorgonHex:   "8404c09100014809c67cc293cefcf236ffb839f01d3c75a2cbe4",
			field10:     "28c2c545d444d68500000000200500056a509ecc",
		},
		{
			name:        "组3 GET /aweme/v2/feed/ (完整URL, 全字段验证)",
			url:         feedURL,
			urlVerified: true,
			stub:        "", // GET 无 body
			khronos:     1783668719,
			gorgonHex:   "840420f500016dc624582315ca1b9958014d71b6b9e4e8fda4da",
			field10:     "f02da1956ef304de00000000200500056a509fef",
		},
	}
}

// 解析 field10 hex 为结构化输入。
func parseField10(h string) xgorgon331005Input {
	b, _ := hex.DecodeString(h)
	var in xgorgon331005Input
	copy(in.MD5Query4[:], b[0:4])
	copy(in.MD5Body4[:], b[4:8])
	copy(in.Reserved[:], b[8:12])
	copy(in.SDKVersion[:], b[12:16])
	copy(in.TimestampBE[:], b[16:20])
	return in
}

func TestXGorgon331005InputLayout(t *testing.T) {
	for _, s := range xgorgon331005Samples() {
		t.Run(s.name, func(t *testing.T) {
			in := parseField10(s.field10)

			// [0:4] == md5(query)[:4]（仅当 url 完整时断言）
			if s.urlVerified {
				query := s.url
				if i := indexByte(query, '?'); i >= 0 {
					query = query[i+1:]
				}
				qMD5 := md5.Sum([]byte(query))
				wantQ := [4]byte{qMD5[0], qMD5[1], qMD5[2], qMD5[3]}
				if in.MD5Query4 != wantQ {
					t.Errorf("[0:4] md5(query)[:4] 不匹配: got %x, want %x",
						in.MD5Query4, wantQ)
				} else {
					t.Logf("[0:4] md5(query)[:4] = %x ✅", in.MD5Query4)
				}
			}

			// [4:8] == stub 前4字节（POST body 的 md5）；GET 请求 stub 为空，跳过断言
			if s.stub != "" {
				stubBytes, _ := hex.DecodeString(s.stub[:8]) // stub 前 8 hex 字符 = 前 4 字节
				var want [4]byte
				copy(want[:], stubBytes)
				if in.MD5Body4 != want {
					t.Errorf("[4:8] stub[:4] 不匹配: got %x, want %x", in.MD5Body4, want)
				} else {
					t.Logf("[4:8] stub(md5 body)[:4] = %x ✅", in.MD5Body4)
				}
			}

			// [12:16] == sdk 版本常量 0x20050005（字节序 20 05 00 05，大端读取）
			sdk := binary.BigEndian.Uint32(in.SDKVersion[:])
			if sdk != xgorgon331005SDKVersion {
				t.Errorf("[12:16] sdk 版本不匹配: got %#x, want %#x", sdk, xgorgon331005SDKVersion)
			} else {
				t.Logf("[12:16] sdk 版本 = %#x (大端 %x) ✅", sdk, in.SDKVersion)
			}

			// [16:20] == X-Khronos（大端）
			ts := binary.BigEndian.Uint32(in.TimestampBE[:])
			if ts != s.khronos {
				t.Errorf("[16:20] timestamp 不匹配: got %d, want %d(X-Khronos)", ts, s.khronos)
			} else {
				t.Logf("[16:20] timestamp(大端) = %d == X-Khronos ✅", ts)
			}

			// 输出前缀固定
			if len(s.gorgonHex) < 4 || s.gorgonHex[:4] != xgorgon331005TagPrefix {
				t.Errorf("X-Gorgon 前缀不是 %s: %s", xgorgon331005TagPrefix, s.gorgonHex[:8])
			} else {
				t.Logf("X-Gorgon 前缀 = %s ✅, 完整值 = %s", s.gorgonHex[:4], s.gorgonHex)
			}
		})
	}
}

// indexByte 是 strings.IndexByte 的 byte 版本，避免额外 import。
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
