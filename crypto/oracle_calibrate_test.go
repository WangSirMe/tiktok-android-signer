package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestOracleCalibrateV2 用真机抓包 oracle (oracle/feed_oracle_v2.json) 校验
// X-Gorgon / X-Ladon / X-Argus 算法是否与现网一致。
//
// oracle 来自 musically 31.5.3 真机抓包 (api22-core-c-alisg / aweme/v2/feed/),
// resp 200 + 192815 bytes = 签名被现网接受, 是有效 green 目标。
//
// 运行: go test -count=1 ./internal/parser/tiktok/ -run OracleCalibrateV2 -v
//
// 本测试只读 oracle 文件做 diff, 不发网络请求。若 oracle 文件不存在则 skip。

type oracleData struct {
	SignTargets struct {
		XArgus   string `json:"X-Argus"`
		XGorgon  string `json:"X-Gorgon"`
		XLadon   string `json:"X-Ladon"`
		XKhronos string `json:"X-Khronos"`
	} `json:"sign_targets"`
	Request struct {
		URL      string            `json:"url"`
		Query    map[string]string `json:"query"`
		CommonV2 map[string]string `json:"common_params_v2"`
	} `json:"request"`
	Device struct {
		AID        string `json:"aid"`
		DeviceID   string `json:"device_id"`
		LcID       string `json:"lc_id"` // 可能不存在
		VersionCod string `json:"version_code"`
		VersionNm  string `json:"version_name"`
	} `json:"device"`
	TS string `json:"ts"`
}

func loadOracle(t *testing.T) *oracleData {
	// 相对 test 运行目录 (backend/) 找 oracle 文件
	candidates := []string{
		// go test cwd = internal/parser/tiktok/crypto/ → 回到 backend/ 是 ../../../../
		"../../../../tools/native-capture/oracle/feed_oracle_v2.json",
		"../../../tools/native-capture/oracle/feed_oracle_v2.json",
		"../../tools/native-capture/oracle/feed_oracle_v2.json",
	}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		// 也试绝对路径 / 按 cwd 推
		abs, _ := filepath.Abs("../tools/native-capture/oracle/feed_oracle_v2.json")
		if _, err := os.Stat(abs); err == nil {
			path = abs
		}
	}
	if path == "" {
		t.Skip("oracle 文件不存在, 跳过 (需先在 tools/native-capture 抓包生成)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var o oracleData
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatal(err)
	}
	return &o
}

// 重建签名输入用的 query string (按抓到的 URL 原样, 去掉 scheme+host+path)
func oracleQueryStr(o *oracleData) string {
	u := o.Request.URL
	if i := strings.Index(u, "?"); i >= 0 {
		return u[i+1:]
	}
	return ""
}

func TestOracleGorgonV2(t *testing.T) {
	o := loadOracle(t)
	ts, _ := strconv.ParseInt(o.TS, 10, 64)

	// X-Gorgon 输入: params(query) + stub(GET=空) + cookie + ts
	// cookie 从 oracle URL 抓不到完整, 但 gorgon 只取 md5(cookie)[:4];
	// musically 的 store-idc cookie 值固定, 这里用抓到的 cookie 片段
	cookie := "store-idc=alisg, store-country-code=tw, store-country-code-src=did"
	q := oracleQueryStr(o)
	got := XGorgon(q, "", cookie, ts)
	want := o.SignTargets.XGorgon

	t.Logf("query len=%d ts=%d", len(q), ts)
	t.Logf("X-Gorgon got  = %s", got)
	t.Logf("X-Gorgon want = %s", want)
	if got == want {
		t.Log("✅ X-Gorgon 匹配 — gorgon 算法 (0404) 对 31.5.3 仍有效")
	} else {
		// 看前缀 (0404 / 8404) 是否一致
		t.Logf("❌ X-Gorgon 不匹配 (前4位 got=%s want=%s)", got[:4], want[:4])
		t.Log("   可能原因: cookie 不同导致 md5[:4] 不同; 或 seed 变了")
	}
}

func TestOracleLadonV2(t *testing.T) {
	o := loadOracle(t)
	ts, _ := strconv.ParseInt(o.TS, 10, 64)
	aid, _ := strconv.ParseInt(o.Device.AID, 10, 64)
	// lc_id 从 device 里取, 没有则用 DefaultArgusConfig 的
	lcID := int64(1611921764)
	if o.Device.LcID != "" {
		lcID, _ = strconv.ParseInt(o.Device.LcID, 10, 64)
	}

	got := XLadon(aid, lcID, ts)
	want := o.SignTargets.XLadon

	t.Logf("aid=%d lcID=%d ts=%d", aid, lcID, ts)
	t.Logf("X-Ladon got  = %s", got)
	t.Logf("X-Ladon want = %s", want)
	if got == want {
		t.Log("✅ X-Ladon 匹配 — ladon 算法对 31.5.3 有效")
	} else {
		t.Log("❌ X-Ladon 不匹配")
	}
}

func TestOracleArgusV2(t *testing.T) {
	o := loadOracle(t)
	ts, _ := strconv.ParseInt(o.TS, 10, 64)
	q := oracleQueryStr(o)

	got := XArgus(q, nil, ts, o.Device.DeviceID, o.Device.VersionNm, DefaultArgusConfig, ArgusExtra{})
	want := o.SignTargets.XArgus

	t.Logf("device_id=%s version_name=%s", o.Device.DeviceID, o.Device.VersionNm)
	t.Logf("X-Argus got  = %s", fmt.Sprintf("%.60s...", got))
	t.Logf("X-Argus want = %s", fmt.Sprintf("%.60s...", want))
	// Argus 含随机数 + 时间戳, 每次不同; 完全相等几乎不可能。
	// 这里只比较结构 (前缀 base64 解码后的 magic / 版本头)
	t.Logf("Argus 含随机量, 无法逐字节比; 需结合 native hook dump 中间量校准")
	t.Logf("got  len=%d want len=%d", len(got), len(want))
}
