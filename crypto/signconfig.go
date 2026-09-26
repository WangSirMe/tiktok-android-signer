package crypto

// ============================================================================
// 签名设备档 — 统一管理
// ============================================================================
// DeviceProfile 汇总签名 + 请求构造所需的全部设备身份、应用版本、区域参数。
// 换设备/升版本时只需改 DefaultDeviceProfile 一处。
//
// 算法本身的协议常量 (魔数、异或掩码、SIMON 常量等) 仍留在各自算法文件里,
// 此文件只管"用哪台设备签"。
// ============================================================================

// DeviceProfile 汇总签名所需的设备身份 + 应用版本 + 区域参数。
type DeviceProfile struct {
	// --- 签名 protobuf 字段 ---
	DeviceID    string // field 5 / URL query device_id
	DeviceType  string // field 23.1 (设备型号, 如 "MI 6X")
	DeviceToken string // field 16 (get_token 下发的 device token,与 did 绑定)
	Channel     string // field 23.3 (固定 "googleplay")
	AppVersion  string // field 7 / URL version_name (如 "33.2.5")
	SdkVersion  string // field 8 (MSSDK version)
	SdkVerCode  int64  // field 9 (MSSDK version code)
	AID         int64  // field 4 / URL aid (TikTok = 1233)
	LcID        int64  // field 6 (license_id)
	DynSeed     string // field 24 (base64, get_seed 下发)
	DynVersion  int    // field 26.1 / field 25 (真机=5)

	// --- 应用版本码 (URL query 用) ---
	VersionCodeShort string // version_code 短码 (如 "330205")
	VersionCodeLong  string // manifest_version_code / update_version_code (如 "2023302050")

	// --- 设备指纹 (URL query + device_register body 用) ---
	DeviceBrand string // device_brand (如 "xiaomi")
	OSVersion   string // os_version (如 "9")
	OSAPI       string // os_api (如 "28")
	Resolution  string // resolution (如 "1080*2030")
	DPI         string // dpi (如 "440")
	CPUABI      string // host_abi (如 "arm64-v8a")
	Language    string // language / app_language (如 "zh-Hans")

	// --- device_register 专属 ---
	InstallID string // install_id / iid
	OpenUDID  string // openudid
	CDID      string // cdid

	// --- 区域 ---
	CurrentRegion  string // current_region (如 "TW")
	SysRegion      string // sys_region (如 "CN")
	OpRegion       string // op_region (如 "TW")
	Residence      string // residence (如 "TW")
	RegionCode     string // region (如 "CN")
	TimezoneName   string // timezone_name (如 "Asia/Shanghai")
	TimezoneOffset string // timezone_offset (如 "28800")
	StoreRegion    string // x-tt-store-region header (如 "tw")

	// --- User-Agent ---
	UserAgent string // 完整 UA 字符串
}

// DefaultDeviceProfile 是当前验证通过的 33.2.5 真机设备档 (MI 6X / alisg-TW)。
// 所有值来自 2026-07-13 真机抓包 + 解密验证。
var DefaultDeviceProfile = DeviceProfile{
	// 签名 protobuf 字段
	DeviceID:    "7659353200026502657",
	DeviceType:  "MI 6X",
	DeviceToken: "",
	Channel:     "googleplay",
	AppVersion:  "33.2.5",
	SdkVersion:  "v05.00.05-ov-android",
	SdkVerCode:  83887392,
	AID:         1233,
	LcID:        2142840551,
	DynSeed:     "",
	DynVersion:  -1,

	// 应用版本码
	VersionCodeShort: "330205",
	VersionCodeLong:  "2023302050",

	// 设备指纹
	DeviceBrand: "xiaomi",
	OSVersion:   "9",
	OSAPI:       "28",
	Resolution:  "1080*2030",
	DPI:         "440",
	CPUABI:      "arm64-v8a",
	Language:    "zh-Hans",

	// device_register 专属
	InstallID: "7659981817244043016",
	OpenUDID:  "a48123e855b77a8c",
	CDID:      "20b73c57-e2a6-4e2c-a85a-ee26bea4d10d",

	// 区域
	CurrentRegion:  "TW",
	SysRegion:      "CN",
	OpRegion:       "TW",
	Residence:      "TW",
	RegionCode:     "CN",
	TimezoneName:   "Asia/Taipei",
	TimezoneOffset: "28800",
	StoreRegion:    "tw",

	// User-Agent
	UserAgent: "com.zhiliaoapp.musically/330205 (Linux; U; Android 9; zh; MI 6X; Build/PKQ1.180904.001; Cronet/TTNetVersion:996128d2 2024-01-12 QuicVersion:ce58f68a 2024-01-12)",
}

// ProfileAsArgusConfig 将设备档转为 ArgusConfig (XArgus 函数签名兼容)。
func ProfileAsArgusConfig(p DeviceProfile) ArgusConfig {
	return ArgusConfig{
		AID:        p.AID,
		LcID:       p.LcID,
		SdkVer:     p.SdkVersion,
		SdkVerCode: p.SdkVerCode,
	}
}

// ProfileAsArgusExtra 将设备档转为 ArgusExtra (XArgus 函数签名兼容)。
// 注意:DeviceToken 不从静态 profile 派生 —— 它与 did 绑定,必须由 get_token
// 动态获取。调用方需自行填入 DeviceToken。
func ProfileAsArgusExtra(p DeviceProfile) ArgusExtra {
	return ArgusExtra{
		DynSeed:    p.DynSeed,
		DynVersion: p.DynVersion,
	}
}
