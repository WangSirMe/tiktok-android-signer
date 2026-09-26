// Package crypto — MSSDK 魔改 zlib deflate 逆向映射表。
//
// 来源:libmetasec_ov.so 33.2.5 arm64-v8a,IDA 反编译 + zlib 1.x 源码对照。
// 逆向手段:hook_br_x1.js 抓 BR X1 目标 → hook_compress2.js 抓 compress2 参数。
//
// ============================================================================
// 为什么需要这份映射表
// ============================================================================
//
// MSSDK 的压缩函数 sub_11D508 是 zlib compress2 的魔改版。标准 Go/C/Python
// zlib 在这段 75B 明文上都选 fixed Huffman (BTYPE=1),而真机选 dynamic Huffman
// (BTYPE=2),导致输出字节不一致。服务端做字节级校验,因此必须逐字节复现。
//
// 3150+ 种标准 zlib 参数组合(level × wbits × memLevel × strategy)全部无法匹配,
// 证明这是算法实现层的差异,必须完整逆向 deflate 引擎。
//
// ============================================================================
// 调用链
// ============================================================================
//
//	sub_E1E60  (入口包装:分配缓冲、初始化结构,OLLVM BR X1 混淆)
//	  └─ BR X1 → 0xE1FA8  (deflate wrapper)
//	       └─ sub_11D508(out, &outlen, in, inlen, level)    = compress2
//	            ├─ level=-1 → Z_DEFAULT_COMPRESSION → 实际 level 6
//	            ├─ dword_1652D4[level] 编码 deflateInit2 参数
//	            ├─ sub_11C4AC(strm, 0, 0, v18)               = deflateInit2_ (魔改)
//	            └─ sub_11C67C(strm, Z_FINISH)                = deflate()
//	                 └─ sub_11C820(strm, flush)              = deflate 内部 (LZ77 + 哈希)
//		              └─ sub_11FB1C(strm, flush)            = _tr_flush_block
//		                   ├─ sub_129D38(strm, use_fixed)   = build_bl_tree + 选择
//		                   └─ sub_11BED8(adler, buf, len)   = adler32 (标准,未改)
//
// ============================================================================
// 函数映射表 (IDA 地址 → zlib 语义)
// ============================================================================
//
//	地址         大小    函数名          zlib 语义              状态
//	-----------  ------  --------------  ---------------------  ------
//	0x11D508     0x1D0   sub_11D508      compress2              ✅ 已还原
//	0x11C4AC     0x190   sub_11C4AC      deflateInit2_ (魔改)   ✅ 参数编码已还原
//	0x11C67C     0x1A4   sub_11C67C      deflate() 驱动循环    ✅ 已还原(标准 zlib)
//	0x11C820     0xC6C   sub_11C820      deflate_fast/slow      ⬜ 待逆向 (LZ77 核心)
//	0x11FB1C     0xA28   sub_11FB1C      _tr_flush_block        ⬜ 待逆向 (块输出)
//	0x129D38     0xFEC   sub_129D38      build_bl_tree + emit   ⬜ 待逆向 (Huffman 树)
//	0x11FA4C     ~60     sub_11FA4C      read_buf               ✅ 已还原
//	0x11BED8     ~190    sub_11BED8      adler32                ✅ 标准,未改
//	0x11C14C     8       sub_11C14C      zcalloc (malloc)       ✅
//	0x11C154     8       sub_11C154      zcfree (free)          ✅
//	0x11D6E0     ~60     sub_11D6E0      deflateBound           ✅ (110*n/100+128)
//	0x137258     ~400    sub_137258      memcpy (libc)          ✅
//	0x137660     ~?      sub_137660      memset (libc)          ✅
//	0x1396FC     ~?      sub_1396FC      ??? (compress2 入口调用) ⬜ 待查
//
// ============================================================================
// 常量表
// ============================================================================
//
//	dword_1652D4[11]  level → deflateInit2 参数编码 (见下方)
//	word_1657C4[258]  length → length_code 映射 (zlib _length_code)
//	unk_165544[512]   distcode low half (距离码表)
//	unk_165744[128]   distcode high half (距离码表)
//	xmmword_164AC0    z_stream 初始模板
//
// dword_1652D4[level] 编码 (真机实测):
//
//	level 0  → 0x0000
//	level 1  → 0x0001
//	level 2  → 0x0006
//	level 3  → 0x0020
//	level 4  → 0x0010
//	level 5  → 0x0020
//	level 6  → 0x0080   ← 真机用 level -1 (Z_DEFAULT_COMPRESSION) → level 6
//	level 7  → 0x0100
//	level 8  → 0x0200
//	level 9  → 0x0300
//	level 10 → 0x05DC
//
// deflateInit2 参数计算 (sub_11D508 line 81):
//
//	v15 = (level < 4) ? 1 : 0        // low_memLevel flag
//	v16 = (level != 0) ? 0x3000 : 0x83000   // wrap bits
//	v18 = (dword_1652D4[v13] & ~(v15<<14)) + (v15<<14) | v16
//
//	对 level 6: v15=0, v16=0x3000
//	  v18 = (0x80 & ~0) + 0 | 0x3000 = 0x3080
//
// sub_11C4AC (deflateInit2_) 参数解码 (a4 = v18):
//
//	*(s+16) = a4                          // 存原始 wparam
//	*(s+20) = ((a4 & 0xFFF) + 2) / 3 + 1  // hash_bits 相关
//	*(s+24) = (((a4>>1)&4) + ((a4>>2)&0x3FF ^ 2)) / 3 + 1
//	*(s+28) = (a4 >> 14) & 1             // memLevel bit
//	if ((a4 & 0x8000)==0) memset(...)     // 初始化 hash table
//
// ============================================================================
// deflate_state 结构体布局 (从 sub_11C4AC/sub_11C820 偏移反推)
// ============================================================================
//
// 这是 zlib deflate_state 的魔改版。偏移不标准,但从字段用法可对应:
//
//	偏移   类型     zlib 字段              依据
//	------ -------  ---------------------  --------------------------------
//	+0     ptr      s->window 或状态       sub_11FA4C read_buf 用 *(s+0)
//	+8     u32      s->???                 sub_11C67C 用 *(s+8) 做 avro 计算
//	+16    u64      s->pending_out / buf   sub_11C67C v7 = *(s+16)
//	+18    u8       flags (bit2=strategy,bit3=...,bit4=header) sub_11FB1C
//	+24    u64      s->next_in 相关        sub_11C67C *(s+24)
//	+32    u32      s->avail_in            sub_11C67C *(s+32) = v5
//	+36    u32      s->??? (matches?)      sub_11FB1C *(s+36) vs *(s+88)
//	+40    u64      s->???                 sub_11C67C v8 = *(s+40)
//	+44    u32      threshold              sub_11FB1C *(s+44) 比较阈值
//	+48    ptr      s->???                 sub_11C4AC 初始化
//	+56    ptr      s->state / strm        sub_11C67C *(s+56)
//	+64    ptr      s->pending_buf         flush_block *(s+64) 写输出
//	+72    ptr      s->pending_buf_end     flush_block 边界检查
//	+80    u32      bit 缓存位宽           flush_block *(s+80) = 8
//	+84    u32      s->??? (sym count?)    flush_block *(s+84) < 0x30 判断
//	+88    u32      s->??? (compressed?)   flush_block *(s+88) vs *(s+36)
//	+92    u32      bit buffer lo          flush_block *(s+92)
//	+96    u32      s->???                 sub_11C67C *(s+96) = *(strm+32)
//	+116   u32      s->avail_out 相关      read_buf *(s+116)
//	+120   u32      s->???                 read_buf 返回值检查
//	+124   u32      s->block_count?        flush_block *(s+124)++
//	+132   u32      s->status              deflate *(v4+132)==1 检查
//	+136   u64      checksum 相关          flush_block
//	+144   ptr      s->??? (output buf)    flush_block/read_buf
//	+152   ptr      &s->total_out          flush_block
//	+160   ptr      &s->avail_out          flush_block/read_buf
//	+168   u64      0                      deflateInit2 清零
//	+176   u64      checksum 相关          flush_block
//	+192   u64      s->??? (out pos)       flush_block/read_buf
//	+200   byte[32768]  s->window (LZ77)   sub_11C820 *(s+200+idx)
//	+32968 byte[32768]  s->prev (mirror)   sub_11C820 *(s+32968+idx)
//	+33226 u16[576]  dyn_ltree freq/count  sub_11C4AC memset 576
//	+33802 u16[64]   dyn_dtree freq/count  sub_11C4AC memset 64
//	+51541 u16[32768] s->head (hash chain) sub_11C820 *(s+51541+idx)
//	+168618 u16[32768] s->prev3 (hash prev) sub_11C820 *(s+168618)
//	+234154 byte[85180] pending/dyn buf    flush_block *(s+234154)
//
// 注:结构体总大小 ≈ 234154 + 85180 ≈ 320KB (zlib deflate_state 约 270KB)。
//
// ============================================================================
// 真机实测数据 (hook_compress2.js 抓取)
// ============================================================================
//
// 输入 (75B protobuf 明文,session/deviceid 随机):
//
//	0a206334616565393930313761383462666438636634646230323063383566306161
//	121337363539333533323030303236353032363537
//	1a07616e64726f6964
//	22097630352e30302e3035
//
// 真机输出 (80B,level=-1→6,BTYPE=2 dynamic Huffman):
//
//	780115c33b0a80300c06e05174d4cd493c40f96d9b3e8e93260db82838787e71f8a64
//	d22f75e2b8ecc2536d32216b5c1430a1998e72527aa818207e013fdf23af0a5cf7de
//	a3ebe200738d007e19f12cc
//
// 标准 C zlib level 6 输出 (80B,但 BTYPE=1 fixed Huffman):
//
//	789ce3524836494c4db5b43430344fb430494a4bb1484e33494932303248b6304d33
//	484c1412363733b53436353632303030323305617329f6c4bc94a2fccc1425ce320
//	3533d03033d035300e19f12cc
//
// 共同点: zlib header (7801 vs 789c — 注意 FLG 不同!), adler32 (e19f12cc)
// 差异点: deflate 块编码 (dynamic vs fixed)
//
// 关键差异分析:
//
//	真机  zlib header = 78 01 (FLEVEL=0, 即 fastest/level 1-3 的标记)
//	标准  zlib header = 78 9c (FLEVEL=2, 即 default/level 4-6 的标记)
//	真机实际用 level 6,但 header 标记 FLEVEL=0 → header 是硬编码的!
//	deflate 体:真机用 dynamic Huffman,标准用 fixed Huffman
//
// 这表明 MSSDK 对 compress2 做了两个魔改:
//  1. zlib header 的 FLEVEL 位硬编码为 0 (不随 level 变化)
//  2. _tr_flush_block 的 fixed/dynamic 选择策略不同 (倾向 dynamic)
package crypto
