package native

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"io"
	"log"
	mrand "math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/WangSirMe/tiktok-android-signer/crypto"
	"github.com/WangSirMe/tiktok-android-signer/crypto/ttdevice"
	"github.com/WangSirMe/tiktok-android-signer/models"
	"github.com/WangSirMe/tiktok-android-signer/parseerr"
	"github.com/WangSirMe/tiktok-android-signer/proxyctx"
)

// ---- v2 签名说明 ----
//
// 签名一律走本包依赖的 crypto 离线实现(X-Gorgon / X-Khronos / X-Ladon / X-Argus,
// 对齐真机 33.2.5 抓包验证)。原 signer-service(unidbg)双轨接缝已随 unidbg
// 方案下线整体移除。

// Native TikTok app API path (v2 pure-algorithm).
//
// Flow (all TikTok official domains, no third-party services):
//  1. device_register on log.tiktokv.com → trusted device_id / install_id
//     (TTEncrypt-wrapped payload, signed). Cached process-wide.
//  2. aweme/v1/aweme/detail/ (single aweme_id) on the edge-passing regional host, signed with the
//     SecSDK stack (X-Gorgon v8404 / X-Khronos / X-Ladon / X-Argus). Requests
//     are issued through an OkHttp TLS fingerprint (bogdanfinn/tls-client) so
//     the edge does not drop them as a non-app client.
//  3. aweme_detail → shared RawItemDetail model (same mapping as embed).
//
// App baseline 对齐真机抓包的 libmetasec_ov.so 版本:**33.2.5**(versionCode 2023302050),
// 设备 Mi 9T Pro / Android 11。query 参数与 header 必须与抓包样本同版本,否则签名
// 上下文不匹配会被 TikTok 拒签。
const (
	nativeRegisterHost = "https://log.tiktokv.com"
	nativeRegisterPath = "/service/2/device_register/"

	// detail 接口 = **POST** /aweme/v1/multi/aweme/detail/(aweme_ids 在 body,非 query)。
	// host 用 **alisg(新加坡)区** —— 2026-07-10 真机 attach 抓包(0x88ee0 sign hook,
	// oracle/live_multi_detail_33.2.5.json)证实:app 打开单视频走的就是这个接口 + 这个区,
	// 不是 useast5。区域由 device_register 按出口 IP 分配(我们的 Clash 7897 出口 = alisg/TW)。
	nativeDetailHost = "https://api22-normal-c-alisg.tiktokv.com"
	nativeDetailPath = "/aweme/v1/multi/aweme/detail/"
)

// nativeDetailBaseURL 是 detail 请求的 host,测试可替换指向 httptest 服务器。
var nativeDetailBaseURL = nativeDetailHost

const (

	// App 33.2.5 — 对齐真机抓包 oracle(live_multi_detail_33.2.5.json)。
	// 设备/版本/区域参数统一从 crypto.DefaultDeviceProfile 派生 (signconfig.go)。

	// 区域档(与 alisg/TW 出口一致,对齐 oracle 的区域参数/header)。
	nativeRegionCode = "CN" // region query param (不在 DeviceProfile 里,协议级常量)

	// 登录态样本值(来自 test_header.txt 真机抓包,33.2.5)。device_register 产不出这些,
	// 先用样本值让签名上下文与真机一致。后续动态登录态从 device_register 响应捕获后替换。
	sampleCookie      = "" //真机登录态样本已清空,可自行抓包填入
	sampleTTToken     = "" //真机样本已清空
	sampleBDClientKey = "" //真机样本已清空
)

// 设备/版本/区域参数 — 全部从 crypto.DefaultDeviceProfile 派生 (signconfig.go 统一管理)。
// 非 const 因为 DefaultDeviceProfile 是 var; 用 var 别名保持 nativeapp.go 内调用简洁。
var (
	nativeFixedDeviceID  = crypto.DefaultDeviceProfile.DeviceID
	nativeVersionName    = crypto.DefaultDeviceProfile.AppVersion
	nativeVersionCode    = crypto.DefaultDeviceProfile.VersionCodeLong
	nativeVersionShort   = crypto.DefaultDeviceProfile.VersionCodeShort
	nativeAndroidUA      = crypto.DefaultDeviceProfile.UserAgent
	nativeDeviceType     = crypto.DefaultDeviceProfile.DeviceType
	nativeDeviceBrand    = crypto.DefaultDeviceProfile.DeviceBrand
	nativeOSVersion      = crypto.DefaultDeviceProfile.OSVersion
	nativeOSAPI          = crypto.DefaultDeviceProfile.OSAPI
	nativeResolution     = crypto.DefaultDeviceProfile.Resolution
	nativeDPI            = crypto.DefaultDeviceProfile.DPI
	nativeCPUABI         = crypto.DefaultDeviceProfile.CPUABI
	nativeLanguage       = crypto.DefaultDeviceProfile.Language
	nativeFixedIID       = crypto.DefaultDeviceProfile.InstallID
	nativeFixedOpenUDID  = crypto.DefaultDeviceProfile.OpenUDID
	nativeFixedCDID      = crypto.DefaultDeviceProfile.CDID
	nativeCurrentRegion  = crypto.DefaultDeviceProfile.CurrentRegion
	nativeSysRegion      = crypto.DefaultDeviceProfile.SysRegion
	nativeOpRegion       = crypto.DefaultDeviceProfile.OpRegion
	nativeResidence      = crypto.DefaultDeviceProfile.Residence
	nativeTimezoneName   = crypto.DefaultDeviceProfile.TimezoneName
	nativeTimezoneOffset = crypto.DefaultDeviceProfile.TimezoneOffset
	nativeStoreRegion    = crypto.DefaultDeviceProfile.StoreRegion
)

// nativeDynAlgo 是 X-Argus field 26 的 dyn algo(1-8)。
// frida 实证:真机 sub_7A9C0 的 W3 在 2~7 动态变化(由 native VM 按请求类型选),
// 与 seed 无绑定。固定用 5(最常见值)——field 26.1 DynVersion = 5*2 = 10。
// dynEncode(algo=5, ...) 走 SM3 哈希分支(xargus.go dynEncode case 5)。
const nativeDynAlgo = 5

type nativeParam struct{ Key, Value string }

// encodeNativeParams builds the query string exactly as sent, so X-Gorgon /
// X-Argus are signed over the same bytes.
func encodeNativeParams(params []nativeParam) string {
	parts := make([]string, 0, len(params))
	for _, p := range params {
		if p.Value == "" {
			// 真机 query 保留空值参数为纯 key(无 =),如 "sdkid&subaid&bd_did&"。
			// get_token 服务端校验 query 完整性,缺这些参数会返回 status=13 拒绝。
			parts = append(parts, urlQueryEscape(p.Key))
			continue
		}
		parts = append(parts, urlQueryEscape(p.Key)+"="+urlQueryEscape(p.Value))
	}
	return strings.Join(parts, "&")
}

// urlQueryEscape 按 TikTok 真机的 query 编码规则编码(对齐 test_url.txt 抓包):
//   - 空格 → '+'(不是 %20;真机 resolution=Mi+9T+Pro 这么写)
//   - '*' 不编码(真机 resolution=1080*1920 这么写)
//   - 其余非保留字符按 %XX 编码
//
// 签名按 URL 原文计算,编码规则必须与真机逐字节一致,否则签名上下文不匹配被拒签。
func urlQueryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~', c == '*':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// generateNativeNumericID returns a positive 19-digit int64 as string.
func generateNativeNumericID() string {
	n := mrand.Int63n(8_200_000_000_000_000_000) + 1_000_000_000_000_000_000
	return strconv.FormatInt(n, 10)
}

// ---- TLS-fingerprinted client (OkHttp / Android) ----

var (
	nativeClientMu   sync.Mutex
	nativeClientInst tls_client.HttpClient
)

func nativeTLSClient() (tls_client.HttpClient, error) {
	nativeClientMu.Lock()
	defer nativeClientMu.Unlock()
	if nativeClientInst != nil {
		return nativeClientInst, nil
	}
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(25),
		tls_client.WithClientProfile(profiles.Okhttp4Android13),
	}
	if p := proxyctx.EffectiveProxyURL(); p != "" {
		opts = append(opts, tls_client.WithProxyUrl(p))
	}
	c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, err
	}
	nativeClientInst = c
	return c, nil
}

// ---- Process-level trusted device (device_register) ----

type nativeDevice struct {
	DeviceID  string
	InstallID string
	CDID      string
	OpenUDID  string
	// Cookie 是 device_register 响应 Set-Cookie 拼成的区域态 cookie
	// (store-idc=alisg / tt-target-idc / store-country-* / ttreq / msToken)。
	// detail 必须带它,否则缺区域路由态被反爬丢包。login=0 匿名,无 session。
	Cookie string
	// SessionKey 从 passport/account/info/v2/ 响应获取。
	// get_seed 的 MSSeedRequest.session 可能与此关联(具体派生关系待确认)。
	SessionKey string
	// Seed / Algorithm 来自 get_seed(ms/get_seed)响应解密:
	//   Seed      = MSSeedResponse.seed(base64)→ X-Argus field 24 dyn_seed
	//   Algorithm = MSSeedResponse.extra_info.algorithm(int)
	// 注:Algorithm(真机实测 14)是 get_seed 下发的服务端配置,与签名时的 dyn algo
	//    (sub_7A9C0 W3,真机 2~7)不是同一个东西。签名 dyn algo 固定用 nativeDynAlgo。
	Seed      string
	Algorithm int
	// DeviceToken 来自 sdi/get_token 响应解密 → X-Argus field 16。
	// 与 did 绑定:用注册的 did 请求 get_token,服务端下发对应 token。
	DeviceToken string
	// GetTokenAttempts 是 get_token 的请求次数(最多重试 3 次)。
	GetTokenAttempts int
	// GetTokenDiag 是 get_token 最后一次失败的诊断(成功时为零值)。
	// 透出到 /api/v2/register 供排查 status=13 等服务端拒绝原因。
	GetTokenDiag GetTokenDiag
}

// GetTokenDiag 是 get_token 失败时的诊断信息,透出到 /api/v2/register。
type GetTokenDiag struct {
	// Status 是 get_token 响应的 HTTP 状态码。
	Status int `json:"status"`
	// StatusCode 是解密明文 field 2 的服务端 status_code(如 13=请求被拒)。
	// 提取自 field 6 解密后的明文,解密失败时为 0。
	StatusCode int `json:"status_code"`
	// StatusMsg 是 StatusCode 对应的可读文案(查表,非服务端下发)。
	// 服务端明文只返回数字码,无文字描述;这里补上便于排查。
	StatusMsg string `json:"status_msg,omitempty"`
	// Raw 是 get_token 响应解析成「字段号→可读值」的结果。
	// field 6 是密文,自动解密后递归 dump(含服务端 status_code 等);解密失败才回落 hex。
	// 无响应时为 nil。
	Raw map[int]any `json:"raw,omitempty"`
	// Err 是请求级错误(网络失败/解码失败等),无请求级错误时为空。
	Err string `json:"err,omitempty"`
}

// msTokenStatusMsg 把 get_token 解密明文 field 2 的 status_code 映射成可读文案。
// 服务端只返回数字码(无文字),此处补中文描述便于排查。未知码返回空串。
// 已知码来自真机抓包与代码注释:
//   - 13:query 完整性校验失败(缺参数/参数为空,如 sdkid/subaid/bd_did)。
func msTokenStatusMsg(code int) string {
	switch code {
	case 0:
		return "" // 成功或无状态码
	case 13:
		return "query 完整性校验失败(缺参数/参数为空)"
	default:
		return ""
	}
}

// dumpProtoFields 把 protobuf wire 字节解析成「字段号→可读值」map。
// varint → int64;bytes → 纯 ASCII 时返回 string,否则返回 "0x"+hex;遇解析错误停止。
// 用于 get_token_diag 把解密明文/原始响应展示成可读结构,而非一堆 hex。
func dumpProtoFields(data []byte) map[int]any {
	return dumpProtoFieldsDecrypt(data, 0)
}

// dumpProtoFieldsDecrypt 同 dumpProtoFields,但当 decryptField > 0 时,
// 该字段的 bytes 视为 MSSDK 密文,自动解密后递归 dump(失败回落 hex)。
// 用于 get_token 响应:field 6 是密文,解密后才能看到 status_code 等服务端信息。
func dumpProtoFieldsDecrypt(data []byte, decryptField int) map[int]any {
	out := make(map[int]any)
	for len(data) > 0 {
		num, wt, n := protowire.ConsumeTag(data)
		if n < 0 {
			return out
		}
		data = data[n:]
		switch wt {
		case protowire.VarintType:
			v, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return out
			}
			data = data[m:]
			out[int(num)] = int64(v)
		case protowire.BytesType:
			b, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return out
			}
			data = data[m:]
			// 指定字段是密文:解密后递归 dump(失败回落 hex/原文)。
			if int(num) == decryptField {
				if pt, e := crypto.MSSDecryptField(b); e == nil && len(pt) > 0 {
					out[int(num)] = dumpProtoFieldsDecrypt(pt, 0)
					continue
				}
			}
			out[int(num)] = protoBytesReadable(b)
		case protowire.Fixed32Type:
			_, m := protowire.ConsumeFixed32(data)
			if m < 0 {
				return out
			}
			data = data[m:]
		case protowire.Fixed64Type:
			_, m := protowire.ConsumeFixed64(data)
			if m < 0 {
				return out
			}
			data = data[m:]
		default:
			return out
		}
	}
	return out
}

// protoBytesReadable 把 bytes 字段转成可读形式:纯 ASCII(含可打印符号)返回原文,否则 hex 前缀。
func protoBytesReadable(b []byte) any {
	if len(b) == 0 {
		return ""
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return "0x" + hex.EncodeToString(truncateBytes(b, 64))
		}
	}
	return string(b)
}

// truncateBytes 截断字节到 maxLen,超出加省略标记(用于诊断展示,避免巨长输出)。
func truncateBytes(b []byte, maxLen int) []byte {
	if len(b) <= maxLen {
		return b
	}
	return b[:maxLen]
}

// 进程级设备缓存已迁移到 devicemgr.go 的 deviceManager(devices):
//   - parse 通过 devices.acquire 取设备(缺失/失效时自动挂到单飞注册排队);
//   - register 通过 devices.publish 发布新设备。

// registerDeviceFull 跑一次完整注册流程(register→get_seed→get_token),
// 内含整体重试:get_token 失败(status=13 设备级风控)时同一 did 重试无效,
// 必须全新 register→get_seed→get_token(换 did)。最多 5 轮,命中即停。
// get_token 5 轮全失败仍返回设备(token 留空,detail 的 X-Argus field 16 置空)。
func registerDeviceFull(ctx context.Context) (*nativeDevice, error) {
	client, err := nativeTLSClient()
	if err != nil {
		return nil, parseerr.UpstreamError(err.Error())
	}
	const maxRounds = 5
	for round := 1; round <= maxRounds; round++ {
		d, err := registerNativeDevice(ctx, client)
		if err != nil {
			// register/seed 级失败(device_id=0 等):换 did 重试,最后一轮才返回 error。
			log.Printf("[register] FAILED round %d/%d: %v", round, maxRounds, err)
			if round == maxRounds {
				return nil, err
			}
			continue
		}
		d.GetTokenAttempts = round
		if d.DeviceToken != "" || round == maxRounds {
			if d.DeviceToken == "" {
				log.Printf("[register] get_token failed after %d rounds (设备级风控)", maxRounds)
			}
			return d, nil
		}
		log.Printf("[register] get_token failed round %d/%d, 整体重试(换 did)", round, maxRounds)
	}
	return nil, parseerr.UpstreamError("device registration: unreachable")
}

func registerNativeDevice(ctx context.Context, client tls_client.HttpClient) (*nativeDevice, error) {
	ts := time.Now().Unix()
	rticket := strconv.FormatInt(ts*1000, 10)
	deviceID := generateNativeNumericID()
	openudid := nativeRandHex(16)
	cdid := nativeRandUUID()

	params := []nativeParam{
		{"ac", "wifi"}, {"channel", "googleplay"}, {"aid", "1233"},
		{"app_name", "musical_ly"}, {"version_code", nativeVersionShort},
		{"version_name", nativeVersionName}, {"device_platform", "android"}, {"os", "android"},
		{"ssmix", "a"}, {"device_type", nativeDeviceType}, {"device_brand", nativeDeviceBrand},
		{"language", nativeLanguage}, {"os_api", nativeOSAPI}, {"os_version", nativeOSVersion},
		{"openudid", openudid}, {"manifest_version_code", nativeVersionCode},
		{"resolution", nativeResolution}, {"dpi", nativeDPI},
		{"update_version_code", nativeVersionCode}, {"_rticket", rticket},
		{"sys_region", nativeSysRegion}, {"region", nativeRegionCode}, {"app_language", nativeLanguage},
		{"carrier_region", nativeCurrentRegion}, {"cdid", cdid}, {"ts", strconv.FormatInt(ts, 10)},
	}
	query := encodeNativeParams(params)

	// register 一律走 crypto.TTEncrypt + 离线签名(已验证可用)。
	var (
		body    []byte
		stub    string
		headers map[string]string
	)
	body = crypto.TTEncrypt(nativeGzip([]byte(deviceRegisterPayload(deviceID, openudid, cdid, ts))))
	bodyMD5 := md5.Sum(body)
	stub = strings.ToUpper(hex.EncodeToString(bodyMD5[:]))
	cfg := crypto.DefaultArgusConfig
	headers = map[string]string{
		"User-Agent":      nativeAndroidUA,
		"Content-Type":    "application/octet-stream;tt-data=a",
		"Accept-Encoding": "gzip",
		"X-SS-STUB":       stub,
		"X-Khronos":       crypto.XKhronos(ts),
		"X-Gorgon":        crypto.XGorgon(query, stub, "", ts),
		"X-Ladon":         crypto.XLadon(cfg.AID, cfg.LcID, ts),
		"X-Argus":         crypto.XArgus(query, bodyMD5[:], ts, deviceID, nativeVersionName, cfg, crypto.ArgusExtra{}),
		"X-SS-REQ-TICKET": rticket,
		"sdk-version":     "2",
	}

	req, err := fhttp.NewRequest(fhttp.MethodPost, nativeRegisterHost+nativeRegisterPath+"?"+query, bytes.NewReader(body))
	if err != nil {
		return nil, parseerr.UpstreamError(err.Error())
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, parseerr.UpstreamError(err.Error())
	}
	defer resp.Body.Close()
	raw := readNativeBody(resp)
	log.Printf("[register] device_register took %s (status=%d, body=%dB)", time.Since(t0), resp.StatusCode, len(raw))

	var reg struct {
		DeviceIDStr  string `json:"device_id_str"`
		InstallIDStr string `json:"install_id_str"`
	}
	_ = json.Unmarshal(raw, &reg)
	// device_register 失败时服务端返回 "0"(非真实 ID),与空串同等视为未注册成功。
	// 返回 error 触发 RegisterDevice 整体重试(换 did 重来)。
	if reg.DeviceIDStr == "" || reg.DeviceIDStr == "0" || reg.InstallIDStr == "" || reg.InstallIDStr == "0" {
		return nil, parseerr.UpstreamError("device_register returned no valid device_id (got " + reg.DeviceIDStr + "/" + reg.InstallIDStr + ")")
	}

	// 捕获区域态 cookie(Set-Cookie):store-idc / tt-target-idc / store-country-* /
	// ttreq / msToken。detail 必须回带,才有正确区域路由态。
	var cookieParts []string
	for _, c := range resp.Cookies() {
		if c.Name == "" {
			continue
		}
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	// install_id 是 iid,真机 cookie 里也带;register 若没 Set-Cookie 就补上。
	cookieStr := strings.Join(cookieParts, "; ")
	if !strings.Contains(cookieStr, "install_id=") {
		if cookieStr != "" {
			cookieStr += "; "
		}
		cookieStr += "install_id=" + reg.InstallIDStr
	}
	// tt-target-idc:register 不下发,但 = 分配到的 store-idc(alisg)。真机 cookie 有此项。
	if idc := extractCookieVal(cookieStr, "store-idc"); idc != "" && !strings.Contains(cookieStr, "tt-target-idc=") {
		cookieStr += "; tt-target-idc=" + idc
	}

	dev := &nativeDevice{
		DeviceID:  reg.DeviceIDStr,
		InstallID: reg.InstallIDStr,
		CDID:      cdid,
		OpenUDID:  openudid,
		Cookie:    cookieStr,
	}
	// warm-up 延迟:device_register 后区域 cookie 需要时间被服务端索引。
	// 不等待直接发 get_seed/detail 会偶发空 200。2 秒足够服务端异步处理。
	tSleep := time.Now()
	//time.Sleep(2 * time.Second)
	log.Printf("[register] warm-up sleep took %s", time.Since(tSleep))
	// get_seed:用新注册的 did 取 seed + algorithm,供 detail X-Argus field 24/26。
	// 失败不阻塞 register(seed 缺失只影响强校验接口,detail 会回退到无 dyn 字段签名)。
	tSeed := time.Now()
	if sd, err := fetchDynSeed(ctx, client, dev); err == nil && sd != nil && sd.Seed != "" {
		log.Printf("[register] get_seed took %s (seed=got, algo=%s)", time.Since(tSeed), sd.Algorithm)
		dev.Seed = sd.Seed
		if alg, atoiErr := strconv.Atoi(sd.Algorithm); atoiErr == nil {
			dev.Algorithm = alg
		}
	} else {
		log.Printf("[register] get_seed took %s (err=%v)", time.Since(tSeed), err)
	}
	// get_token:用新注册的 did 取 device_token,供 detail X-Argus field 16。
	// 单次请求;失败不在此处重试(status=13 是设备级风控,同一 did 重试无效),
	// 由 RegisterDevice 整体重试(全新 register→get_seed→get_token,换 did)。
	tToken := time.Now()
	token, diag := fetchGetToken(ctx, client, dev)
	dev.GetTokenAttempts = 1
	if token != "" {
		dev.DeviceToken = token
		dev.GetTokenDiag = GetTokenDiag{}
		log.Printf("[register] get_token took %s (token=got)", time.Since(tToken))
	} else {
		dev.GetTokenDiag = diag
		log.Printf("[register] get_token failed (took %s)", time.Since(tToken))
	}
	return dev, nil
}

// DeviceRegistration 是 device_register 的可序列化产物:新注册设备的身份标识 +
// 区域态 cookie。供 /api/v2/register 端点透出给调用方。
type DeviceRegistration struct {
	DeviceID  string `json:"device_id"`
	InstallID string `json:"install_id"`
	CDID      string `json:"cdid"`
	OpenUDID  string `json:"openudid"`
	// Cookie 是 device_register 响应 Set-Cookie 拼成的区域态 cookie
	// (store-idc / tt-target-idc / ttreq / msToken 等)。
	Cookie string `json:"cookie"`
	// Seed 是注册完成后用该设备身份请求 get_seed(ms/dyn/task)的产物。
	// 下发 dyn_seed / device_token(X-Argus 强校验字段)。注册成功但 get_seed
	// 失败时为 nil —— 不阻塞 register 主流程(get_seed 仅强校验接口需要)。
	Seed *DynSeedResult `json:"seed,omitempty"`
	// DeviceToken 来自 sdi/get_token 响应解密(→ X-Argus field 16)。
	// 与 did 绑定:get_token 成功时为 25 字节字符串,失败(3 次重试均失败)为空。
	DeviceToken string `json:"device_token,omitempty"`
	// GetTokenDiag 是 get_token 最后一次失败的诊断(成功时为 nil 省略)。
	// 含 field6 解密明文(hex)+ HTTP status + 原始响应(hex),供排查服务端拒绝原因。
	// 用指针:成功时置 nil,JSON omitempty 才能完全省略(值类型 struct 无法省略)。
	GetTokenDiag *GetTokenDiag `json:"get_token_diag,omitempty"`
	// GetTokenAttempts 是 get_token 的请求次数(最多重试 3 次)。
	GetTokenAttempts int `json:"get_token_attempts"`
}

// RegisterDevice 执行一次 device_register(log.tiktokv.com),返回新注册设备的
// 身份标识 + 区域态 cookie。每次调用都注册一个全新设备,供 /api/v2/register
// 端点显式取设备用;注册结果同时通过 devices.publish 发布为当前进程设备
// (parse 直接消费,无需先调 /api/v2/register)。
//
// 注册成功后,立即用新设备的 did/iid 请求 get_seed(ms/dyn/task),把 get_seed
// 下发的 dyn_seed/device_token 一起透出。仅请求 TikTok 官方域名(log-va +
// mssdk-va)。
func RegisterDevice(ctx context.Context) (*DeviceRegistration, error) {
	tStart := time.Now()
	dev, err := registerDeviceFull(ctx)
	if err != nil {
		return nil, err
	}
	// 发布为进程级当前设备,供 /api/v2/parse 取用。
	devices.publish(dev)

	reg := &DeviceRegistration{
		DeviceID:         dev.DeviceID,
		InstallID:        dev.InstallID,
		CDID:             dev.CDID,
		OpenUDID:         dev.OpenUDID,
		Cookie:           dev.Cookie,
		DeviceToken:      dev.DeviceToken,
		GetTokenAttempts: dev.GetTokenAttempts,
	}
	// get_token 失败时透出诊断(DeviceToken 为空=失败)。成功时不赋值,JSON 省略。
	if dev.DeviceToken == "" {
		diag := dev.GetTokenDiag
		reg.GetTokenDiag = &diag
	}
	// get_seed/get_token 结果(registerNativeDevice 内部已取,这里只透出给响应)。
	if dev.Seed != "" {
		reg.Seed = &DynSeedResult{
			Seed:       dev.Seed,
			Algorithm:  strconv.Itoa(dev.Algorithm),
			StatusCode: 200,
		}
	}
	log.Printf("[register] total %s (did=%s)", time.Since(tStart), dev.DeviceID)
	return reg, nil
}

// ---- MSSDK get_seed ----
//
// device_register 之后、detail 之前的冷启动链第一步(get_seed → ri/report →
// sdi/get_token)。真机抓包(mitm live-single.mitm + 用户提供的真机 URL)确认实际
// 请求为 **POST** https://mssdk22-normal-alisg.tiktokv.com/ms/get_seed?<query>。
// query 带新注册设备的 did=device_id / iid=install_id;**请求体是一个 protobuf**:
//
//   package MSSdk;
//   message MSSeedRequest {
//     string session     = 1;  // SecSDK 会话标识(随机生成)
//     string deviceid    = 2;  // = device_id
//     string os          = 3;  // 固定 "android"
//     string sdk_version = 4;  // = sdk_ver(nativeSeedSDKVer)
//   }
//
// 响应也是 protobuf(MSSeedResponse):field 1 = seed(下发的 dyn_seed,见下)。
// get_seed 下发的 seed 进入 X-Argus field 24(dyn_seed),是 multi/aweme/detail
// 等强校验接口 X-Argus 的必需输入。
//
// host = mssdk22-normal-alisg(区域随出口 IP:alisg/TW 出口走 alisg 后缀,与 detail
// 同区)。POST 是实测:GET 同 URL 返回 404 page not found,POST 返回 200。
//
// sdk_version 两套值(frida hook 0x11101C 实抓 MSSeedRequest 明文确认,见
// oracle/hook_get_seed_field4.jsonl):
//   - URL query 的 sdk_ver  = v05.00.05-alpha.10-ov-android (长版,真机抓包)
//   - POST body field 4     = v05.00.05                    (短版,frida 实抓)
// 两者并存,分别填到 query 和 body。
//
// 加密:body 的 MSSeedRequest 明文经 MSSEncodeRequest 加密后作为 field-4 整体发送。
// 加密链 = zlib → customTEA(xxTEA×48) → first_flag → AES-128-CBC(详见 crypto/mssdk_seed.go)。
// frida 实抓明文 = 4 字段 protobuf(session=32hex随机 / deviceid / os / sdk_version),
// 完全匹配用户提供的 MSSeedRequest schema。

const (
	nativeSeedHost = "https://mssdk22-normal-alisg.tiktokv.com"
	nativeSeedPath = "/ms/get_seed"
	// URL query 用的长版 sdk_ver。
	nativeSeedSDKVer = "v05.00.05-alpha.10-ov-android"
	// POST body field 4 的短版 sdk_version(frida 实抓)。
	nativeSeedSDKVerBody = "v05.00.05"

	// sdi/get_token(device_token 来源)。host = mssdk22(与 get_seed 同节点:真机抓包
	// flows-v2.mitm 实证 get_token 走 mssdk22,非 mssdk16)。
	nativeTokenHost = "https://mssdk22-normal-alisg.tiktokv.com"
	nativeTokenPath = "/sdi/get_token"
)

// DynSeedResult 是 get_seed (ms/get_seed) 的产物:服务端下发的 seed(MSSeedResponse.seed
// → X-Argus field 24 dyn_seed)+ 解析出的 extra_info.algorithm + 原始响应(供调试)。
type DynSeedResult struct {
	Seed       string `json:"seed"`                // MSSeedResponse.seed → X-Argus field 24 dyn_seed
	Algorithm  string `json:"algorithm,omitempty"` // MSSeedResponse.extra_info.algorithm
	Raw        string `json:"raw"`                 // 原始响应体摘要(hex 前缀),供调试/对拍
	StatusCode int    `json:"status_code"`
}

// buildDynSeedParams 构造 GET ms/get_seed 的 query 参数。字段与顺序逐一对齐真机
// attach 抓包(oracle/hook_liziz_v2.jsonl 的 ms.bd.o.k.b CALL 记录):
// did/iid 取自刚刚 device_register 下发的值,其余取自统一设备档。
func buildDynSeedParams(dev *nativeDevice) []nativeParam {
	return []nativeParam{
		{"lc_id", strconv.FormatInt(crypto.DefaultArgusConfig.LcID, 10)},
		{"platform", "android"},
		{"device_platform", "android"},
		{"sdk_ver", nativeSeedSDKVer},
		{"sdk_ver_code", strconv.FormatInt(crypto.DefaultDeviceProfile.SdkVerCode, 10)},
		{"app_ver", nativeVersionName},
		{"version_code", nativeVersionCode},
		{"aid", strconv.FormatInt(crypto.DefaultArgusConfig.AID, 10)},
		{"sdkid", ""},
		{"subaid", ""},
		{"iid", dev.InstallID},
		{"did", dev.DeviceID},
		{"bd_did", ""},
		{"client_type", "inhouse"},
		{"region_type", "ov"},
		{"mode", "2"},
	}
}

// buildMSSeedRequest 构造 get_seed 的 POST 请求体明文(MSSeedRequest protobuf),
// 返回的明文会被 caller 用 MSSEncodeRequest 加密(zlib+customTEA+AES-CBC)后整体发送。
//
// schema(frida hook 0x11101C 实抓,oracle/hook_get_seed_field4.jsonl mode=4 确认):
//
//	message MSSeedRequest {
//	  string session     = 1;  // 32 hex 随机(nativeRandHex(16))
//	  string deviceid    = 2;  // = dev.DeviceID
//	  string os          = 3;  // "android"
//	  string sdk_version = 4;  // "v05.00.05"(短版,不是 URL query 的长版)
//	}
//
// 用 protowire 手写,避免为 4 个字段单独生成 .pb.go。
func buildMSSeedRequest(dev *nativeDevice) []byte {
	// session:随机生成(account/info 已删除,不再用 session_key)。
	session := nativeRandHex(32)
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType) // session
	b = protowire.AppendString(b, session)
	b = protowire.AppendTag(b, 2, protowire.BytesType) // deviceid
	b = protowire.AppendString(b, dev.DeviceID)
	b = protowire.AppendTag(b, 3, protowire.BytesType) // os
	b = protowire.AppendString(b, "android")
	b = protowire.AppendTag(b, 4, protowire.BytesType)  // sdk_version
	b = protowire.AppendString(b, nativeSeedSDKVerBody) // 短版 v05.00.05
	return b
}

// parseMSSeedResponse 解析 get_seed 的 MSSeedResponse。
//
// 响应体是加密的(和请求 body 同构):
//
//	outer_protobuf {
//	  field1 = 响应 magic(varint,0x40240624)
//	  field2 = 2
//	  field5 = 4
//	  field6 = AES 密文(bytes) → 解密后 = MSSeedResponse protobuf
//	}
//
// 解密链(field6 → 明文)= AES-128-CBC → customTEA → zlib(标准 78 da):
//
//	plaintext = MSSeedResponse {
//	  string seed       = 1;  // ~132B base64
//	  ExtraInfo extra_info = 2 { string algorithm = 1; }
//	}
//
// 返回 seed 与 extra_info.algorithm。解析容错:解密失败或字段缺失返回空串。
func parseMSSeedResponse(raw []byte) (seed, algorithm string) {
	// 1. 解析外层 protobuf,取 field6 密文
	var field6 []byte
	for len(raw) > 0 {
		num, wt, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return seed, algorithm
		}
		raw = raw[n:]
		if wt != protowire.BytesType {
			m := protowire.ConsumeFieldValue(num, wt, raw)
			if m < 0 {
				return seed, algorithm
			}
			raw = raw[m:]
			continue
		}
		val, m := protowire.ConsumeBytes(raw)
		if m < 0 {
			return seed, algorithm
		}
		raw = raw[m:]
		if num == 6 {
			field6 = val
		}
	}
	if len(field6) == 0 {
		return seed, algorithm
	}

	// 2. 解密 field6 → MSSeedResponse 明文 protobuf
	plain, err := crypto.MSSDecryptField(field6)
	if err != nil || len(plain) == 0 {
		return seed, algorithm
	}

	// 3. 解析明文 MSSeedResponse { seed=1, extra_info=2 }
	for len(plain) > 0 {
		num, wt, n := protowire.ConsumeTag(plain)
		if n < 0 {
			return seed, algorithm
		}
		plain = plain[n:]
		if wt != protowire.BytesType {
			m := protowire.ConsumeFieldValue(num, wt, plain)
			if m < 0 {
				return seed, algorithm
			}
			plain = plain[m:]
			continue
		}
		val, m := protowire.ConsumeBytes(plain)
		if m < 0 {
			return seed, algorithm
		}
		plain = plain[m:]
		switch num {
		case 1: // seed (string)
			seed = string(val)
		case 2: // extra_info (message)
			algorithm = parseExtraInfoAlgorithm(val)
		}
	}
	return seed, algorithm
}

// parseExtraInfoAlgorithm 解析 MSSeedResponse.extra_info 的 algorithm 字段。
//
// extra_info = { string algorithm = 1; }
// algorithm 是单字节编号(1~16),决定后续签名 VM 用哪种加密算法变体。
// 真机以 bytes(len=1) 编码,值是非可打印字节(如 0x06/0x0a/0x10),
// 直接 string() 会在 JSON 里显示成 "\u0006"/"\n" 不直观,这里转十进制字符串。
func parseExtraInfoAlgorithm(raw []byte) string {
	for len(raw) > 0 {
		num, wt, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return ""
		}
		raw = raw[n:]
		if wt != protowire.BytesType {
			m := protowire.ConsumeFieldValue(num, wt, raw)
			if m < 0 {
				return ""
			}
			raw = raw[m:]
			continue
		}
		val, m := protowire.ConsumeBytes(raw)
		if m < 0 {
			return ""
		}
		raw = raw[m:]
		if num == 1 { // algorithm (单字节编号)
			if len(val) == 1 {
				return strconv.Itoa(int(val[0]))
			}
			return string(val)
		}
	}
	return ""
}

// fetchDynSeed 用刚注册的设备身份请求 get_seed(ms/get_seed)。失败不致命:
// get_seed 下发的 seed 用于 X-Argus field 24,但离线签名路用 signconfig.go
// 的固定样本值也能跑。这里任何错误(网络/非 2xx/空响应)
// 都返回 nil result + error,由调用方决定是否继续。
//
// POST:MSSEncodeRequest(MSSeedRequest 明文) 作为请求体。GET 同 URL 返 404 page not found。
// 无签名头,与 device_register 同域级 *.tiktokv.com。
//
// 加密链(frida 真机完整逆向,见 crypto/mssdk_seed.go):
//
//	protobuf → zlib → [header] → customTEA(xxTEA×48) → first_flag → AES-128-CBC
//
// key/tea_key/loop 均为 get_seed 专用常量(详见 mssdk_seed.go 注释)。
func fetchDynSeed(ctx context.Context, client tls_client.HttpClient, dev *nativeDevice) (*DynSeedResult, error) {
	ts := time.Now().Unix()
	query := encodeNativeParams(buildDynSeedParams(dev))
	fullURL := nativeSeedHost + nativeSeedPath + "?" + query

	// 1. 明文 MSSeedRequest → MSSEncodeRequest 加密(zlib+customTEA+AES-CBC,真机逐字节验证)。
	plain := buildMSSeedRequest(dev)
	aesCT, err := crypto.MSSEncodeRequest(plain)
	if err != nil {
		return nil, parseerr.UpstreamError("get_seed encode: " + err.Error())
	}

	// 2. 外层 protobuf 包装(真机 body 实抓 mitm 确认):
	//    field 1 = SDK magic(固定值,非 timestamp! 真机 0x40400844 = 2020/04/22 build date << 1)
	//    field 2 = 2(varint,固定)
	//    field 3 = 4(varint,固定)
	//    field 4 = AES 密文(bytes)
	var body []byte
	body = protowire.AppendTag(body, 1, protowire.VarintType)
	body = protowire.AppendVarint(body, 0x40400844) // SDK magic(真机冷启动实抓)
	body = protowire.AppendTag(body, 2, protowire.VarintType)
	body = protowire.AppendVarint(body, 2)
	body = protowire.AppendTag(body, 3, protowire.VarintType)
	body = protowire.AppendVarint(body, 4)
	body = protowire.AppendTag(body, 4, protowire.BytesType)
	body = protowire.AppendBytes(body, aesCT)

	// 3. x-ss-stub = MD5(完整 body) 大写 hex(真机 mitm 验证:MD5(整个 protobuf body))。
	bodyMD5 := md5.Sum(body)
	stub := strings.ToUpper(hex.EncodeToString(bodyMD5[:]))

	// 4. 签名头(照真机 mitm 抓包逐字段对齐)。get_seed 强校验 X-Argus,
	//    缺四件套会被服务端拒(error 2,无 seed 下发)。
	cfg := crypto.DefaultArgusConfig
	xKhronos := crypto.XKhronos(ts)
	xGorgon := crypto.XGorgon(query, stub, dev.Cookie, ts)
	xLadon := crypto.XLadon(cfg.AID, cfg.LcID, ts)
	xArgus := crypto.XArgus(query, bodyMD5[:], ts, dev.DeviceID, nativeVersionName, cfg,
		crypto.ArgusExtra{})
	rticket := strconv.FormatInt(ts*1000, 10)

	req, err := fhttp.NewRequest(fhttp.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, parseerr.UpstreamError(err.Error())
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	// 请求头逐字段对齐真机 mitm(mssdk22-normal-alisg.tiktokv.com/ms/get_seed)。
	req.Header.Set("Cookie", dev.Cookie)
	req.Header.Set("X-Tt-Request-Tag", "t=0;n=0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Vc-Bdturing-Sdk-Version", "2.3.5.i18n")
	req.Header.Set("X-Tt-Dm-Status", "login=0;ct=0;rt=7")
	req.Header.Set("X-Ss-Req-Ticket", rticket)
	// 真机 get_seed 用 octet-stream(无 tt-data=a 后缀 —— body 是 MSSDK 自有加密,非 TTEncrypt)。
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Ss-Stub", stub)
	req.Header.Set("X-Tt-Store-Region", nativeStoreRegion)
	req.Header.Set("X-Tt-Store-Region-Src", "did")
	req.Header.Set("Rpc-Persist-Pyxis-Policy-V-Tnc", "1")
	req.Header.Set("X-Ss-Dp", "1233")
	req.Header.Set("X-Tt-Trace-Id", nativeTraceID())
	req.Header.Set("User-Agent", nativeAndroidUA)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("X-Khronos", xKhronos)
	req.Header.Set("X-Gorgon", xGorgon)
	req.Header.Set("X-Ladon", xLadon)
	req.Header.Set("X-Argus", xArgus)

	resp, err := client.Do(req)
	if err != nil {
		return nil, parseerr.UpstreamError(err.Error())
	}
	defer resp.Body.Close()
	raw := readNativeBody(resp)

	out := &DynSeedResult{
		Raw:        dynSeedRawDigest(raw),
		StatusCode: resp.StatusCode,
	}
	if len(raw) > 0 {
		seed, algo := parseMSSeedResponse(raw)
		out.Seed = seed
		out.Algorithm = algo
	}
	return out, nil
}

// dynSeedRawDigest 把 get_seed 的二进制响应压缩成可放进 JSON 的字符串:
// 短响应原样 UTF-8,长响应(>256B)只放长度 + hex 前缀。供响应输出/调试,非签名字段。
func dynSeedRawDigest(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if len(raw) <= 256 {
		// 可打印 ASCII 直接输出,否则 hex
		printable := true
		for _, b := range raw {
			if b < 0x20 || b > 0x7e {
				printable = false
				break
			}
		}
		if printable {
			return string(raw)
		}
	}
	n := len(raw)
	if n > 64 {
		n = 64
	}
	return fmt.Sprintf("(len=%d,hex=%s)", len(raw), hex.EncodeToString(raw[:n]))
}

// ---- sdi/get_token(device_token 来源)----

// buildMSTokenRequest 构造 get_token 请求明文 protobuf。
//
// 真机抓包解密后结构(13 字段,field1=605B 固定设备详情):
//
//	field1  = 设备详情 message(固定,msTokenDeviceDetail 常量)
//	field3  = "android"
//	field4  = sdk_ver 长版(v05.00.05-alpha.10-ov-android)
//	field5  = 167774784(varint,固定)
//	field6  = "1233"(aid)
//	field7  = "33.2.5"(app_ver)
//	field8  = device_id(动态,= dev.DeviceID)
//	field9  = "0401000000000000"(固定)
//	field11 = 1999997(varint,固定)
//	field15 = "!notset!"
//	field16 = 1999997(varint,固定)
//
// 加密链与 get_seed 完全相同(MSSEncodeRequest),只是外层 field3=2(get_seed 是 4)。
func buildMSTokenRequest(dev *nativeDevice) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType) // field1 设备详情(cdid 动态)
	b = protowire.AppendBytes(b, buildDeviceDetail(dev.CDID))
	b = protowire.AppendTag(b, 3, protowire.BytesType) // os
	b = protowire.AppendString(b, "android")
	b = protowire.AppendTag(b, 4, protowire.BytesType) // sdk_ver 长版
	b = protowire.AppendString(b, nativeSeedSDKVer)
	b = protowire.AppendTag(b, 5, protowire.VarintType) // 固定 flag
	b = protowire.AppendVarint(b, 167774784)
	b = protowire.AppendTag(b, 6, protowire.BytesType) // aid
	b = protowire.AppendString(b, "1233")
	b = protowire.AppendTag(b, 7, protowire.BytesType) // app_ver
	b = protowire.AppendString(b, nativeVersionName)
	b = protowire.AppendTag(b, 8, protowire.BytesType) // device_id(动态)
	b = protowire.AppendString(b, dev.DeviceID)
	b = protowire.AppendTag(b, 9, protowire.BytesType) // 固定
	b = protowire.AppendString(b, "0401000000000000")
	b = protowire.AppendTag(b, 11, protowire.VarintType) // 固定
	b = protowire.AppendVarint(b, 1999997)
	b = protowire.AppendTag(b, 15, protowire.BytesType) // !notset!
	b = protowire.AppendString(b, "!notset!")
	b = protowire.AppendTag(b, 16, protowire.VarintType) // 固定
	b = protowire.AppendVarint(b, 1999997)
	return b
}

// buildDeviceDetail 构造 get_token 请求明文 field1 的设备详情 message。
//
// 用 ttdevice.DeviceInfo proto struct 填充固定设备档(MI 6X / Android 9 / alisg-TW),
// 仅 install_uuid(field 26)注入 register 生成的动态 cdid,其余 54 字段为固定档值。
// proto.Marshal 输出与历史 hex 模板逐字节 IDENTICAL(605B):本 message 无任何字段等于
// proto3 默认值(字符串占位用 "!notset!",整数占位用 1999997),默认值省略规则不触发;
// protoc 按字段号升序写,与抓包顺序一致。由 nativeapp_devicedetail_test.go 锁定不变量。
//
// 换设备档需重新抓包并更新下方字面量;空 cdid 视为占位,仍用固定模板值。
func buildDeviceDetail(cdid string) []byte {
	const placeholder = "!notset!"
	if cdid == "" {
		cdid = "00000000-0000-0000-0000-000000000000"
	}
	d := &ttdevice.DeviceInfo{
		DeviceBrand:       placeholder,
		Manufacturer:      "xiaomi",
		DeviceModel:       "MI 6X",
		DeviceName:        placeholder,
		OsName:            "Android",
		OsVersion:         "9",
		ScreenResolution:  "1080*2160",
		ScreenDpi:         880,
		RomBuildId:        "PKQ1.180904.001",
		Field10:           3115884974,
		Locale:            "zh_CN",
		Timezone:          "Asia/Shanghai,8",
		TzOffset:          2748,
		Field14:           200,
		MemTotalBytes:     7842717696,
		StorageTotalA:     108308496384,
		StorageTotalB:     108308496384,
		StorageFree:       33828290560,
		IdSlot_19:         placeholder,
		IdSlot_20:         placeholder,
		IdSlot_21:         placeholder,
		IdSlot_22:         placeholder,
		IdSlot_23:         placeholder,
		DeviceFingerprint: "l23TqOWNfpc9gUso6mP9QUVVCB/zWytzZ/EZ8FoVdas=",
		TimestampA:        3568087524,
		InstallUuid:       cdid,
		DiskCapacity:      743640924160,
		Field28:           placeholder,
		Sentinel_29:       1999997,
		Sentinel_30:       1999997,
		Slot_31:           placeholder,
		Slot_32:           placeholder,
		Slot_33:           placeholder,
		Slot_34:           placeholder,
		Slot_35:           placeholder,
		Sentinel_36:       1999997,
		Sentinel_37:       1999997,
		Slot_38:           placeholder,
		Slot_39:           placeholder,
		NetIpList:         `["10.0.0.1","0.0.0.0"]`,
		Sentinel_41:       1999997,
		Sentinel_42:       1999997,
		Slot_44:           placeholder,
		Field45:           3419633858,
		TimestampB:        3568087566,
		ApkPath:           "/data/app/com.zhiliaoapp.musically-cFIVgW3RVOkCGNb_T8PdQw==/base.apk",
		Field48:           56,
		Sentinel_49:       1999997,
		Slot_50:           placeholder,
		Sentinel_51:       1999997,
		Sentinel_52:       1999997,
		Slot_53:           placeholder,
		Slot_54:           placeholder,
		Slot_55:           placeholder,
		Sentinel_56:       1999997,
	}
	out, err := proto.Marshal(d)
	if err != nil {
		// DeviceInfo 是静态结构,字段类型与值在编译期确定,Marshal 不可能失败。
		panic(fmt.Sprintf("buildDeviceDetail: proto.Marshal 失败(不应发生): %v", err))
	}
	return out
}

// parseMSTokenResponse 解析 get_token 响应,提取 device_token。
//
// 响应结构与 get_seed 同构(外层 protobuf + field6 加密):
//
//	outer { field1=0x40240624, field2=2, field5=2, field6=密文 }
//	解密后 = { string device_token = 1; varint status = 2; }
//
// device_token 是 25 字节字符串(如 "A-U9XM7JkE--2WHYU1gQoGw3u"),→ X-Argus field 16。
func parseMSTokenResponse(raw []byte) (deviceToken string) {
	// 1. 解析外层取 field6
	var field6 []byte
	for len(raw) > 0 {
		num, wt, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return deviceToken
		}
		raw = raw[n:]
		if wt != protowire.BytesType {
			m := protowire.ConsumeFieldValue(num, wt, raw)
			if m < 0 {
				return deviceToken
			}
			raw = raw[m:]
			continue
		}
		val, m := protowire.ConsumeBytes(raw)
		if m < 0 {
			return deviceToken
		}
		raw = raw[m:]
		if num == 6 {
			field6 = val
		}
	}
	if len(field6) == 0 {
		return deviceToken
	}
	// 2. 解密 field6 → 明文 protobuf
	plain, err := crypto.MSSDecryptField(field6)
	if err != nil || len(plain) == 0 {
		return deviceToken
	}
	// 3. 取 field1 = device_token
	for len(plain) > 0 {
		num, wt, n := protowire.ConsumeTag(plain)
		if n < 0 {
			return deviceToken
		}
		plain = plain[n:]
		if wt != protowire.BytesType {
			m := protowire.ConsumeFieldValue(num, wt, plain)
			if m < 0 {
				return deviceToken
			}
			plain = plain[m:]
			continue
		}
		val, m := protowire.ConsumeBytes(plain)
		if m < 0 {
			return deviceToken
		}
		plain = plain[m:]
		if num == 1 {
			return string(val)
		}
	}
	return deviceToken
}

// fetchGetToken 用注册的 did 请求 sdi/get_token,获取 device_token(→ X-Argus field 16)。
//
// 请求层与 fetchDynSeed 高度同构(同加密链 MSSEncodeRequest + 同签名头),
// 差异:host=mssdk16 / path=/sdi/get_token / 外层 field3=2 / 明文=buildMSTokenRequest。
// 失败不致命:返回空 token + 失败诊断,detail 的 X-Argus field 16 留空,不回退任何固定档。
func fetchGetToken(ctx context.Context, client tls_client.HttpClient, dev *nativeDevice) (string, GetTokenDiag) {
	return fetchGetTokenWithArgus(ctx, client, dev, "")
}

// fetchGetTokenWithArgus 同 fetchGetToken,但允许覆盖 X-Argus(空串用默认签名)。
// xArgusOverride="_SKIP_" 时不发送 X-Argus 头(对照实验用)。
// 返回 (token, diag):token 非空=成功;token 空=失败,diag 带解密明文+原始响应。
func fetchGetTokenWithArgus(ctx context.Context, client tls_client.HttpClient, dev *nativeDevice, xArgusOverride string) (string, GetTokenDiag) {
	ts := time.Now().Unix()
	query := encodeNativeParams(buildDynSeedParams(dev))
	fullURL := nativeTokenHost + nativeTokenPath + "?" + query

	plain := buildMSTokenRequest(dev)
	aesCT, err := crypto.MSSEncodeRequest(plain)
	if err != nil {
		return "", GetTokenDiag{Err: "MSSEncodeRequest: " + err.Error()}
	}

	var body []byte
	body = protowire.AppendTag(body, 1, protowire.VarintType)
	body = protowire.AppendVarint(body, 0x40400844)
	body = protowire.AppendTag(body, 2, protowire.VarintType)
	body = protowire.AppendVarint(body, 2)
	body = protowire.AppendTag(body, 3, protowire.VarintType)
	body = protowire.AppendVarint(body, 2)
	body = protowire.AppendTag(body, 4, protowire.BytesType)
	body = protowire.AppendBytes(body, aesCT)

	bodyMD5 := md5.Sum(body)
	stub := strings.ToUpper(hex.EncodeToString(bodyMD5[:]))

	cfg := crypto.DefaultArgusConfig
	xKhronos := crypto.XKhronos(ts)
	xGorgon := crypto.XGorgon(query, stub, dev.Cookie, ts)
	xLadon := crypto.XLadon(cfg.AID, cfg.LcID, ts)
	// get_token 的 X-Argus 必须带 field 24(dyn_seed)+field 26(dyn payload),
	// 否则服务端返回 status=13 拒绝(真机抓包验证)。seed/algo 来自 get_seed,
	// 此处复用 dev 缓存(= 上一步 fetchDynSeed 写入的值)。
	argusExtra := crypto.ArgusExtra{
		DynSeed:    dev.Seed,
		DynVersion: dev.Algorithm >> 1,
	}
	xArgus := crypto.XArgus(query, bodyMD5[:], ts, dev.DeviceID, nativeVersionName, cfg,
		argusExtra)
	if xArgusOverride != "" && xArgusOverride != "_SKIP_" {
		xArgus = xArgusOverride
	}
	rticket := strconv.FormatInt(ts*1000, 10)

	req, err := fhttp.NewRequest(fhttp.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return "", GetTokenDiag{Err: "NewRequest: " + err.Error()}
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	req.Header.Set("Cookie", dev.Cookie)
	req.Header.Set("X-Tt-Request-Tag", "t=0;n=1")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Vc-Bdturing-Sdk-Version", "2.3.5.i18n")
	req.Header.Set("X-Tt-Dm-Status", "login=0;ct=0;rt=7")
	req.Header.Set("X-Ss-Req-Ticket", rticket)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Ss-Stub", stub)
	req.Header.Set("X-Tt-Store-Region", nativeStoreRegion)
	req.Header.Set("X-Tt-Store-Region-Src", "did")
	req.Header.Set("Rpc-Persist-Pyxis-Policy-V-Tnc", "1")
	req.Header.Set("X-Ss-Dp", "1233")
	req.Header.Set("X-Tt-Trace-Id", nativeTraceID())
	req.Header.Set("User-Agent", nativeAndroidUA)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("X-Khronos", xKhronos)
	req.Header.Set("X-Gorgon", xGorgon)
	req.Header.Set("X-Ladon", xLadon)
	if xArgusOverride != "_SKIP_" {
		req.Header.Set("X-Argus", xArgus)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[get_token] FAILED req err: %v", err)
		log.Printf("[get_token] REQ url=%s", fullURL)
		log.Printf("[get_token] REQ cookie=%s", dev.Cookie)
		log.Printf("[get_token] REQ x-argus=%s x-gorgon=%s x-ladon=%s x-khronos=%s stub=%s",
			xArgus, xGorgon, xLadon, xKhronos, stub)
		log.Printf("[get_token] REQ body(%dB)=%x", len(body), body)
		return "", GetTokenDiag{Err: "client.Do: " + err.Error()}
	}
	defer resp.Body.Close()
	raw := readNativeBody(resp)
	if len(raw) == 0 {
		log.Printf("[get_token] FAILED empty response, status=%d", resp.StatusCode)
		log.Printf("[get_token] REQ url=%s", fullURL)
		log.Printf("[get_token] REQ cookie=%s", dev.Cookie)
		log.Printf("[get_token] REQ x-argus=%s x-gorgon=%s x-ladon=%s x-khronos=%s stub=%s",
			xArgus, xGorgon, xLadon, xKhronos, stub)
		log.Printf("[get_token] REQ body(%dB)=%x", len(body), body)
		return "", GetTokenDiag{Status: resp.StatusCode, Err: "empty response"}
	}
	token := parseMSTokenResponse(raw)
	if token != "" {
		return token, GetTokenDiag{}
	}
	// 解析响应外层,field 6(密文)自动解密后递归 dump → 一处看清 status_code 等。
	diag := GetTokenDiag{Status: resp.StatusCode, Raw: dumpProtoFieldsDecrypt(raw, 6)}
	// 解密明文提取 field 2(status_code),查表补可读 msg。服务端只返回数字码。
	if f6 := extractField6(raw); len(f6) > 0 {
		if pt, e := crypto.MSSDecryptField(f6); e == nil && len(pt) > 0 {
			if code, ok := extractVarintField(pt, 2); ok {
				diag.StatusCode = int(code)
				diag.StatusMsg = msTokenStatusMsg(int(code))
			}
			if diag.StatusCode != 0 {
				log.Printf("[get_token] FAILED no token, status_code=%d msg=%s", diag.StatusCode, diag.StatusMsg)
			} else {
				log.Printf("[get_token] FAILED no token, status=%d raw=%d", resp.StatusCode, len(raw))
			}
		} else if e != nil {
			log.Printf("[get_token] FAILED no token, decrypt err=%v", e)
			diag.Err = "MSSDecryptField: " + e.Error()
		}
	} else {
		log.Printf("[get_token] FAILED no token, status=%d raw=%d", resp.StatusCode, len(raw))
		diag.Err = "no field6 in response"
	}
	log.Printf("[get_token] REQ url=%s", fullURL)
	log.Printf("[get_token] REQ cookie=%s", dev.Cookie)
	log.Printf("[get_token] REQ x-argus=%s x-gorgon=%s x-ladon=%s x-khronos=%s stub=%s",
		xArgus, xGorgon, xLadon, xKhronos, stub)
	log.Printf("[get_token] REQ body(%dB)=%x", len(body), body)
	log.Printf("[get_token] RESP status=%d raw(%dB)=%x", resp.StatusCode, len(raw), raw)
	return "", diag
}

// extractField6 从外层 protobuf 提取 field6 bytes。
func extractField6(raw []byte) []byte {
	return extractBytesField(raw, 6)
}

// extractVarintField 从 protobuf 明文提取指定 field 号的 varint 值。
// 用于从 get_token 解密明文取 field 2(status_code)。找不到返回 (0,false)。
func extractVarintField(data []byte, field int) (uint64, bool) {
	for len(data) > 0 {
		num, wt, n := protowire.ConsumeTag(data)
		if n < 0 {
			return 0, false
		}
		data = data[n:]
		if int(num) == field && wt == protowire.VarintType {
			v, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return 0, false
			}
			return v, true
		}
		m := protowire.ConsumeFieldValue(num, wt, data)
		if m < 0 {
			return 0, false
		}
		data = data[m:]
	}
	return 0, false
}

// extractBytesField 从 protobuf 提取指定 field 号的首个 LEN(bytes)字段。内部复用。
func extractBytesField(raw []byte, field int) []byte {
	for len(raw) > 0 {
		num, wt, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return nil
		}
		raw = raw[n:]
		if wt != protowire.BytesType {
			m := protowire.ConsumeFieldValue(num, wt, raw)
			if m < 0 {
				return nil
			}
			raw = raw[m:]
			continue
		}
		val, m := protowire.ConsumeBytes(raw)
		if m < 0 {
			return nil
		}
		raw = raw[m:]
		if int(num) == field {
			return val
		}
	}
	return nil
}

// ---- item detail via POST multi/aweme/detail ----

// buildMultiDetailParams 构造 POST multi/aweme/detail 的 **query** 参数(不含 aweme_ids,
// 后者在 body)。字段与顺序逐一对齐真机 attach 抓包 oracle
// (oracle/live_multi_detail_33.2.5.json,MI 6X / alisg-TW / 33.2.5)。签名按 URL 原文算,
// 这里改一个字段都可能导致签名上下文不匹配被拒。
func buildMultiDetailParams(dev *nativeDevice, ts int64) []nativeParam {
	rticket := strconv.FormatInt(ts*1000, 10)
	return []nativeParam{
		{"share_link_mode", "0"},
		{"share_scene", "1"},
		{"device_platform", "android"},
		{"os", "android"},
		{"ssmix", "a"},
		{"_rticket", rticket},
		{"cdid", dev.CDID},
		{"channel", "googleplay"},
		{"aid", "1233"},
		{"app_name", "musical_ly"},
		{"version_code", nativeVersionShort},
		{"version_name", nativeVersionName},
		{"manifest_version_code", nativeVersionCode},
		{"update_version_code", nativeVersionCode},
		{"ab_version", nativeVersionName},
		{"resolution", nativeResolution},
		{"dpi", nativeDPI},
		{"device_type", nativeDeviceType},
		{"device_brand", nativeDeviceBrand},
		{"language", nativeLanguage},
		{"os_api", nativeOSAPI},
		{"os_version", nativeOSVersion},
		{"ac", "wifi"},
		{"is_pad", "0"},
		{"current_region", nativeCurrentRegion},
		{"app_type", "normal"},
		{"sys_region", nativeSysRegion},
		{"timezone_name", nativeTimezoneName},
		{"residence", nativeResidence},
		{"app_language", nativeLanguage},
		{"timezone_offset", nativeTimezoneOffset},
		{"host_abi", nativeCPUABI},
		{"locale", nativeLanguage},
		{"ac2", "wifi5g"},
		{"uoo", "1"},
		{"op_region", nativeOpRegion},
		{"build_number", nativeVersionName},
		{"region", nativeRegionCode},
		{"ts", strconv.FormatInt(ts, 10)},
		{"iid", dev.InstallID},
		{"device_id", dev.DeviceID},
		{"openudid", dev.OpenUDID},
	}
}

// buildMultiDetailBody 构造 POST body:aweme_ids=[<vid>]&request_source=0(URL 编码)。
// 返回 body 字节与其大写 MD5(= X-SS-STUB)。
func buildMultiDetailBody(itemID string) ([]byte, string) {
	body := []byte("aweme_ids=" + urlQueryEscape("["+itemID+"]") + "&request_source=0")
	sum := md5.Sum(body)
	return body, strings.ToUpper(hex.EncodeToString(sum[:]))
}

// nativeSignHeaders 构造 detail 请求的签名头(crypto 离线签名),并返回签名产物
// (供探针/调试对拍:完整 URL + 上下文 header + 4 签 + TikTok 原始响应)。
func nativeSignHeaders(ctx context.Context, fullURL string, ctxHeaders []nativeParam, queryStr string, ts int64, deviceID string, extra crypto.ArgusExtra) (map[string]string, *models.SignArtifact, error) {
	// 纯 Go 离线签名(已对齐真机 33.2.5 验证通过)。先并入全部 ctxHeaders
	// (cookie / x-ss-stub / 区域头 / content-* 等 POST detail 必需头),再叠加 crypto
	// 现算的 4 签。
	//
	// **x-ss-stub = MD5(body)**:从 ctxHeaders 取(buildMultiDetailBody 已算好大写
	// md5(body))。X-Gorgon / X-Argus 的原料含 x-ss-stub,必须用真值参与签名——否则
	// 服务端收 POST 后重算 MD5(body) 与我们上传的 x-ss-stub 不符,直接拒(空 200)。
	// POST 时 X-Argus field 13 = SM3(MD5(body) 的 16 字节原始值)[:6],不是 body 本身。
	cfg := crypto.DefaultArgusConfig
	var stub string
	var cookie string
	var stubMd5 []byte // POST: MD5(body) 的 16 字节原始值,作为 X-Argus field 13 输入
	h := make(map[string]string, len(ctxHeaders)+4)
	signHeaders := make([]models.SignHeader, 0, len(ctxHeaders))
	for _, p := range ctxHeaders {
		h[p.Key] = p.Value
		signHeaders = append(signHeaders, models.SignHeader{Key: p.Key, Value: p.Value})
		switch p.Key {
		case "x-ss-stub":
			stub = p.Value
			// stub 是大写 md5 hex(32字符),转回 16 字节原始值供 X-Argus field 13
			if b, err := hex.DecodeString(strings.ToLower(stub)); err == nil && len(b) == 16 {
				stubMd5 = b
			}
		case "cookie":
			cookie = p.Value
		}
	}
	xKhronos := crypto.XKhronos(ts)
	// X-Gorgon 原料含 MD5(Cookie):必须用请求实际携带的 cookie 参与签名。
	xGorgon := crypto.XGorgon(queryStr, stub, cookie, ts)
	xLadon := crypto.XLadon(cfg.AID, cfg.LcID, ts)
	xArgus := crypto.XArgus(queryStr, stubMd5, ts, deviceID, nativeVersionName, cfg, extra)
	h["X-Khronos"] = xKhronos
	h["X-Gorgon"] = xGorgon
	h["X-Ladon"] = xLadon
	h["X-Argus"] = xArgus
	// 返回签名产物(完整 URL + 全部上下文 header + 4 签),供 API 响应输出。
	// FetchViaNativeAppAPI 会把 TikTok 响应填进 sign.Result。
	sign := &models.SignArtifact{
		URL:      fullURL,
		Headers:  signHeaders,
		XArgus:   xArgus,
		XGorgon:  xGorgon,
		XKhronos: xKhronos,
		XLadon:   xLadon,
	}
	return h, sign, nil
}

// nativeDetailContextHeaders 返回 POST multi/aweme/detail 的上下文 header(除 4 签外),有序。
// 这些 header 既是要发给 TikTok 的请求头,也是 unidbg 签名的输入(header 上下文)。
// 字段/顺序逐一对齐真机 attach 抓包 oracle(oracle/live_multi_detail_33.2.5.json)。
//
// **匿名(login=0)**:cookie 只带 device_register 返回的区域态(store-idc=alisg 等),
// 无任何 session/passport 登录态——oracle 证实 login=0 匿名即可取到视频数据。
// x-ss-stub / content-length 绑定 POST body;x-tt-trace-id 每请求随机生成。
func nativeDetailContextHeaders(ts int64, dev *nativeDevice, stub string, contentLen int) []nativeParam {
	rticket := strconv.FormatInt(ts*1000, 10)
	return []nativeParam{
		{"cookie", dev.Cookie},
		{"sdk-version", "2"},
		{"x-tt-dm-status", "login=0;ct=0;rt=7"},
		{"x-ss-req-ticket", rticket},
		{"passport-sdk-version", "19"},
		{"x-vc-bdturing-sdk-version", "2.3.5.i18n"},
		{"content-type", "application/x-www-form-urlencoded; charset=UTF-8"},
		{"x-ss-stub", stub},
		{"content-length", strconv.Itoa(contentLen)},
		{"x-tt-store-region", nativeStoreRegion},
		{"x-tt-store-region-src", "did"},
		{"rpc-persist-pyxis-policy-v-tnc", "1"},
		{"x-ss-dp", "1233"},
		{"x-tt-trace-id", nativeTraceID()},
		{"user-agent", nativeAndroidUA},
		{"ttzip-version", "40244"},
		{"accept-encoding", "gzip"}, // 只收 gzip:服务端据此 gzip 压缩,readNativeBody 可解;避开 br/ttzip
	}
}

// nativeBuildCurl 把签名后的完整请求封装成一条可直接在终端重放的 curl 命令。
// 仅用于对拍/调试:复制 sign.curl 到 shell 即可复现发给 TikTok 的请求。
// header 顺序不稳定(map 遍历),但内容与实际请求逐字段一致。
func nativeBuildCurl(fullURL string, headers map[string]string, body string) string {
	var b strings.Builder
	b.WriteString("curl -X POST ")
	b.WriteString(shellQuote(fullURL))
	// header 按原始上下文顺序输出更易读,但此处只有 map;用排序保证稳定。
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	// 简单插入排序(key 数量小,避免额外 import sort)。
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	for _, k := range keys {
		b.WriteString(" \\\n  -H ")
		b.WriteString(shellQuote(k + ": " + headers[k]))
	}
	if body != "" {
		b.WriteString(" \\\n  --data ")
		b.WriteString(shellQuote(body))
	}
	return b.String()
}

// shellQuote 用单引号包裹字符串,内部单引号转义为 '\”。适用于 sh/bash/zsh。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// nativeTraceID 生成 x-tt-trace-id:00-<32hex>-<16hex>-01(每请求唯一)。
func nativeTraceID() string {
	a := make([]byte, 16)
	b := make([]byte, 8)
	_, _ = rand.Read(a)
	_, _ = rand.Read(b)
	return "00-" + hex.EncodeToString(a) + "-" + hex.EncodeToString(b) + "-01"
}

// FetchViaNativeAppAPI fetches the video via **POST** /aweme/v1/multi/aweme/detail/
// on the alisg regional host, matching the real-app request captured live
// (oracle/live_multi_detail_33.2.5.json): aweme_ids in the body, region
// cookies/headers from device_register, anonymous (login=0). Maps aweme_detail(s)
// to the shared RawItemDetail model.
//
// 设备来自 deviceManager:启动预热 / parse 失败自动重注册,调用方无需先调
// /api/v2/register。注册产物有时效与请求次数限制 —— 设备被拒(空响应)时
// invalidate + 等待重注册的新设备重试一轮。重注册受 1 分钟阈值限制:
// 已有注册在跑则等它跑完取结果;纯冷却窗口(无注册可等)直接报错。
func FetchViaNativeAppAPI(ctx context.Context, itemID string) (*RawItemDetail, error) {
	client, err := nativeTLSClient()
	if err != nil {
		return nil, parseerr.UpstreamError(err.Error())
	}
	dev, gen, err := devices.acquire(ctx)
	if err != nil {
		return nil, err
	}
	detail, rejected, err := nativeDetailOnce(ctx, client, dev, itemID)
	if !rejected {
		return detail, err
	}
	// 设备被风控/配额耗尽:标记失效并触发重注册(全局 1 分钟仅一次),
	// 等新设备到手后重试一轮。
	fresh, err := devices.invalidateAndRefresh(ctx, gen)
	if err != nil {
		return nil, err
	}
	detail, rejected, err = nativeDetailOnce(ctx, client, fresh, itemID)
	if !rejected {
		return detail, err
	}
	// 新设备仍被拒:不再立即重注册(1 分钟阈值),报错由客户端稍后重试。
	return nil, parseerr.UpstreamError("native app API returned empty response (signature rejected by anti-bot)")
}

// nativeDetailOnce 用指定设备身份请求一次 multi/aweme/detail。返回:
//   - detail:成功时的解析结果(部分失败时可能只带 Sign)
//   - rejected:设备被拒(raw 为空 = 签名/设备被反爬静默丢弃),调用方应换设备重试
//   - err:非设备级错误(网络/视频私有等)
func nativeDetailOnce(ctx context.Context, client tls_client.HttpClient, dev *nativeDevice, itemID string) (*RawItemDetail, bool, error) {
	// 用 register 注册出来的真实设备身份(did/iid/openudid/cdid + 区域 cookie + seed)。
	// seed/algorithm 来自 register 链路里的 get_seed,与 did 绑定自洽。
	// X-Gorgon 签名原料含 MD5(cookie),cookie 已含 register 下发的 install_id,无需替换。
	freshDev := *dev

	ts := time.Now().Unix()
	params := buildMultiDetailParams(&freshDev, ts)
	queryStr := encodeNativeParams(params)
	fullURL := nativeDetailBaseURL + nativeDetailPath + "?" + queryStr

	// POST body:aweme_ids=[vid]&request_source=0;stub=大写 md5(body)。
	body, stub := buildMultiDetailBody(itemID)
	ctxHeaders := nativeDetailContextHeaders(ts, &freshDev, stub, len(body))

	// X-Argus 动态 seed + device_token(来自 get_seed/get_token)。
	// seed 与 did 绑定;device_token 必须来自 get_token 且与 did 绑定,
	// 不用任何固定档回退 —— get_token 失败则 field 16 留空。
	//
	// DynVersion(dyn algo):frida 实证 sub_7A9C0 的 W3 在 2~7 动态变化(与 seed 无绑定,
	// 由 native VM 内部按请求类型选)。固定用 5(真机最常见值,对应 field 26.1=10)。
	// field 26.1 = DynVersion*2、dynEncode 用 DynVersion(algo)在 xargus.go 里已处理。
	argusExtra := crypto.ArgusExtra{
		DynSeed:    freshDev.Seed,
		DynVersion: freshDev.Algorithm >> 1,
	}
	if freshDev.DeviceToken != "" {
		argusExtra.DeviceToken = freshDev.DeviceToken
	}
	headers, sign, err := nativeSignHeaders(ctx, fullURL, ctxHeaders, queryStr, ts, freshDev.DeviceID, argusExtra)
	if err != nil {
		return nil, false, err
	}
	// 把 POST body 透出到签名产物,供响应输出对拍(X-SS-STUB 应 = MD5(Body))。
	if sign != nil {
		sign.Body = string(body)
		// 封装完整 curl 命令(url + 签名后 headers + body),便于直接重放对拍。
		sign.Curl = nativeBuildCurl(fullURL, headers, string(body))
	}

	req, err := fhttp.NewRequest(fhttp.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, false, parseerr.UpstreamError(err.Error())
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, parseerr.UpstreamError(err.Error())
	}
	defer resp.Body.Close()
	raw := readNativeBody(resp)

	// 临时探针(DEBUG_NATIVE=1):核对 x-ss-stub 是否 = MD5(body),并打响应元信息。
	// logid 非空 = 请求到达 TikTok 应用层;rawLen=0 = 被反爬静默丢弃。
	if os.Getenv("DEBUG_NATIVE") == "1" {
		sum := md5.Sum(body)
		recomputed := strings.ToUpper(hex.EncodeToString(sum[:]))
		fmt.Printf("[native-detail] item=%s bodyLen=%d body=%q\n"+
			"  x-ss-stub(sent)=%s\n  md5(body)      =%s  match=%v\n"+
			"  status=%d logid=%s rawLen=%d\n",
			itemID, len(body), string(body),
			headers["x-ss-stub"], recomputed, headers["x-ss-stub"] == recomputed,
			resp.StatusCode, resp.Header.Get("X-Tt-Logid"), len(raw))
	}

	// 把 TikTok 原始响应填进签名产物(供探针对拍)。
	if sign != nil {
		sign.Result = string(raw)
	}

	if len(raw) == 0 {
		// App anti-bot silently dropped the request(签名/设备被风控,或注册产物
		// 时效/次数配额耗尽)。上报 rejected:调用方 invalidate 当前设备并等待
		// 单飞重注册的新设备后重试。
		return nil, true, nil
	}

	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		snippet := string(raw)
		if len(snippet) > 160 {
			snippet = snippet[:160]
		}
		return nil, false, parseerr.UpstreamError("native app API returned non-JSON: " + strings.ReplaceAll(snippet, "\n", " "))
	}
	detail, err := ParseItemDetailResponse(data, itemID)
	if err != nil {
		// TikTok 明确拒绝该视频(status_code 3020004 "unavailable video default" /
		// 私密 / 不存在)时必须把错误冒泡到 API 层,返回 success:false + 错误信息;
		// 旧逻辑在 sign 非 nil(crypto 路径恒真)时吞错,导致 /api/v2/parse 对
		// 下架视频返回 200 + downloads:[] + success:true。
		return nil, false, err
	}
	detail.Sign = sign
	return detail, false, nil
}

// ---- helpers ----

func readNativeBody(resp *fhttp.Response) []byte {
	raw, _ := io.ReadAll(resp.Body)
	// 按 Content-Encoding 解压:gzip / br(brotli)/ deflate 都兜住,
	// 解不了就返回原始字节(调用方自行判断)。
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "gzip":
		if zr, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
			if dec, err := io.ReadAll(zr); err == nil {
				return dec
			}
		}
	case "br":
		if dec, err := io.ReadAll(brotli.NewReader(bytes.NewReader(raw))); err == nil && len(dec) > 0 {
			return dec
		}
	case "deflate":
		if dec, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw))); err == nil && len(dec) > 0 {
			return dec
		}
	}
	return raw
}

// extractCookieVal 从 "k=v; k2=v2" 的 cookie 串里取指定 key 的值(无则空)。
func extractCookieVal(cookie, key string) string {
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, key+"=") {
			return part[len(key)+1:]
		}
	}
	return ""
}

func nativeRandHex(n int) string {
	b := make([]byte, n/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func nativeRandUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// nativeGzip gzips data and zeroes the 10-byte header's mtime/XFL/OS bytes,
// matching the app's TTEncrypt input normalization.
func nativeGzip(data []byte) []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(data)
	_ = zw.Close()
	out := buf.Bytes()
	for i := 3; i < 10 && i < len(out); i++ {
		out[i] = 0
	}
	return out
}

// deviceRegisterPayload 构造 device_register 加密 body。设备指纹全部取自统一设备档
// 常量(Mi 9T Pro / Android 11 / 33.2.5),与 register query 和 detail 三处一致,
// 避免注册身份与请求/签名身份不符被风控丢包。数字型 JSON 字段(*_version_code /
// os_api / density_dpi)用 %s 注入字符串常量,输出为不带引号的数字,仍是合法 JSON。
func deviceRegisterPayload(deviceID, openudid, cdid string, ts int64) string {
	return fmt.Sprintf(`{"magic_tag":"ss_app_log","header":{"display_name":"TikTok","update_version_code":%s,"manifest_version_code":%s,"app_version_minor":"","aid":1233,"channel":"googleplay","package":"com.zhiliaoapp.musically","version_name":"%s","version_code":%s,"sdk_version":"3.9.17","os":"Android","os_version":"%s","os_api":%s,"device_model":"%s","device_brand":"%s","device_manufacturer":"%s","cpu_abi":"%s","release_build":"7e6048c_20231219","density_dpi":%s,"display_density":"xxhdpi","resolution":"%s","language":"en","timezone":8,"access":"wifi","not_request_sender":0,"carrier":"","mcc_mnc":"","region":"TW","tz_name":"Asia/Taipei","tz_offset":28800,"sim_region":"tw","openudid":"%s","cdid":"%s","clientudid":"%s","sig_hash":"194326e82c84a639a52e5c023116f12a","device_platform":"android","google_aid":"%s","apk_first_install_time":%d,"is_system_app":0,"sdk_flavor":"global"},"_gen_time":%d}`,
		nativeVersionCode, nativeVersionCode, nativeVersionName, nativeVersionShort,
		nativeOSVersion, nativeOSAPI, nativeDeviceType, nativeDeviceBrand, nativeDeviceBrand,
		nativeCPUABI, nativeDPI, nativeResolution,
		openudid, cdid, nativeRandUUID(), nativeRandUUID(), ts*1000-86400000, ts*1000)
}
