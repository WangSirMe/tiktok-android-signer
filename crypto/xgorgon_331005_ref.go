// Package crypto 的 X-Gorgon 逆向参考资料（TikTok 33.2.5 真机验证）。
//
// 这个文件不是生产实现，而是「真机独立验证」的结论记录，供后期：
//   - 校验 crypto/xgorgon.go (iqbalmh18 / app 37.0.4 移植版) 与 33.2.5 真机的差异
//   - 当 8404 版本签名需要复活时，作为输入布局 / 字节序 / 算法来源的权威参考
//
// ── 来源 ──────────────────────────────────────────────────────────────
// 逆向原文：看雪论坛《[原创]unidbg读写跟踪还原X-Gorgon》
//
//	（版本 33.2.5，mssdk libmetasec_ov.so，关键加密函数 0x7e530，包装 0x811a8）
//
// 真机验证脚本：backend/tools/native-capture/frida/verify_xgorgon.js
// 原始抓包数据：/tmp/verify_xgorgon_out*.jsonl（frida 三方对拍：native hook
//
//	0x88ee0 入口 / 0x811a8 包装 / 0x7e530 核心 + TTNet Request Java 层 header）
//
// ── 验证结论（3 组真机数据逐字段命中）──────────────────────────────────
// 0x7e530 入口的 20 字节明文输入（X0 对象 +0x10 字段指向的 20 字节 buffer），
// 按大端读，布局如下：
//
//	偏移    含义                 真机实测(组3, GET /aweme/v2/feed/)   验证方式
//	[0:4]   md5(query)[:4]       F02DA195 == md5(query)[:4]          计算 md5(query) 前4字节 ✅
//	[4:8]   md5(body)[:4]        D444D685 == x-ss-stub[:8]           header x-ss-stub 前4字节 ✅
//	[8:12]  (feed为0)            00000000                            feed 请求该分量为 0
//	[12:16] sdk 版本(大端)       20050005 == 0x20050005             三组数据完全一致，固定常量 ✅
//	[16:20] timestamp(大端)      6A509ECC == X-Khronos(1783668428)   大端读 == X-Khronos header ✅
//
// 关键纠正点（与 crypto/xgorgon.go 移植版的差异）：
//  1. [12:16] 不是全零，而是 sdk 版本常量 0x20050005（字节序 20 05 00 05，大端读取）。
//     现有移植版 (iqbalmh18/37.0.4) 这里写死 0,0,0,0，与 33.2.5 真机不符。
//     这正是交接文档记录的「30.8.4 密钥/布局被现网拒收」的根因之一。
//  2. [16:20] timestamp 是大端 4 字节（网络字节序），不是 hex(ts) 字符串。
//     文章 dump 的 67 90 66 CC 也是大端；现有移植版按 hex(ts)[:4] 拼，字节布局不同。
//  3. 输出前 4 字节 "8404" 后紧跟的 2 字节是 malloc 堆地址低位（随机，原文明示
//     「可以当成随机数」），所以示例串 8404e0a6... 无法逐字节复现——这点原文未讲清。
//
// ── 输出结构（26 字节 hex = 52 字符）──────────────────────────────────
//
//	8404 [seed2][seed3] 0001 [20字节 RC4 变种加密输出]
//	  ↑ 固定  ↑ malloc 低位(随机) ↑ 固定
//	真机组1: 8404 c091 0001 4809c67cc293cefcf236ffb839f01d3c75a2cbe4
//	真机组2: 8404 2018 0001 59219f82dff9bc440410445e501fe4486f8c3212
//
// 加密算法（原文 unidbg trace 还原，RC4 变种）：
//   - 0x7f6f4 处循环初始化 256 表 S[i]=i
//   - 0x7fca8 处用 8 字节 key（由输入派生）做 KSA 式置换
//   - 0x801cc 处逐字节加密：S 盒查表 + orr/and/sub/eor 位运算混合
//   - 0x804e8 处最终写回（每字节 3 次写入）
//     加密链：0x7e530(0x7e648取对象字段) → 0x801cc(逐字节混淆) → 0x804e8(写回)
//
// 调用链（IDA xref 已印证）：
//
//	0x88ee0 → 0x87e48 → 0x86d60 → 0x6B14c
//	  ├ 0x6Db40 → 0x73908 → 0x7d3f0  (X-Argus)
//	  ├           0x73968 → 0x7dd18  (X-Ladons)
//	  └           0x73688 → 0x811a8  (X-Gorgon) ← 0x8217c → 0x7e530(核心)
package crypto

// 下面是一组只读常量，用于文档化 33.2.5 真机验证的输入布局。
// 它们不被生产路径引用，仅供测试 / 后期复活签名时对照。
// 若日后需要让 Go 实现对齐 33.2.5，应据此修正 xgorgon.go 的 XGorgon()。

const (
	// xgorgon331005InputLen 是 0x7e530 的明文输入长度（字节）。
	xgorgon331005InputLen = 20

	// xgorgon331005SDKVersion 是 [12:16] 的 sdk 版本常量，按大端读取的值。
	// 真机三组数据此字段字节序恒为 20 05 00 05 → Big-Endian u32 = 0x20050005。
	xgorgon331005SDKVersion uint32 = 0x20050005

	// xgorgon331005TagPrefix 是输出 hex 的固定前缀（版本标识 + 固定 "0001"）。
	// 真机："8404" + 2字节随机 + "0001" + 40 hex。
	xgorgon331005TagPrefix = "8404"
	xgorgon331005MidFix    = "0001"
)

// XGorgon331005Input 唯一用途：把 33.2.5 真机验证的输入布局编码成 Go 结构，
// 便于测试以「文档即代码」的方式锁定结论。不导出，非生产。
//
// 所有字段按「内存中的大端字节序」记录（与 0x7e530 入口 buffer 的实际存储一致）。
type xgorgon331005Input struct {
	MD5Query4   [4]byte // [0:4]  md5(url query)[:4]
	MD5Body4    [4]byte // [4:8]  md5(POST body)[:4]，GET 请求此处参与运算但非0
	Reserved    [4]byte // [8:12] feed 请求实测为 0
	SDKVersion  [4]byte // [12:16] 字节序恒为 20 05 00 05（大端 u32 = 0x20050005）
	TimestampBE [4]byte // [16:20] Unix 秒时间戳，大端；值 == X-Khronos header
}
