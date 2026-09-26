package crypto

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/WangSirMe/tiktok-android-signer/crypto/mflate"
)

// MSSDK get_seed 加密层(libmetasec_ov.so sub_11101C → VM)。
//
// 完整加密链(用户完整逆向 + frida 真机验证):
//
//	plaintext(MSSeedRequest protobuf)
//	  → zlib 压缩(sub_E1E60),输出 = [长度前缀4B LE] + [zlib 流]
//	  → cal_flag_one(len) + cal_flag_two(zlib)   // 1-4B 头部
//	  → data = one_flag + header_two + compressed
//	  → custom_tea_encrypt(data, tea_key, xor_key)  // xxTEA 单block × 48
//	  → first_flag 覆盖 teaCT 前(在密文最前面插 1B,值 = 原首字节|3)
//	  → raw_aes = first_flag + teaCT + random(4)
//	  → aes_cbc_encrypt(raw_aes, aes_key, aes_iv)   // 最终密文 = field-4
//
// 真机确认(libmetasec_ov.so 33.2.5 arm64-v8a):
//   - AES = AES-128-CBC + PKCS7(hook sub_149EAC 验证)
//   - aes_key = b8d72ddec05142948bbf2dc81d63759c(bswap 前 de2dd7b8...;sign_key 派生)
//   - aes_iv  = d6c3969582f9ac5313d39c180b54a2bc(sign_key 派生)
//   - tea_key = bd992378addecefa3031303234303430(get_seed 专用 16B 常量,hook 0x1140DC X0)
//   - tea loop = 48(get_tea_loop_count(random_LE);random LE % 5 = 2 → 2*8+32=48)
//   - zlib magic 78 01
//
// 注:tea_key 是 get_seed 专用常量,与 report 协议的 tea_key(49d75939... 派生)不同。

// ---------- AES-128-CBC(已确认)----------

// mssdkAESKey 是 get_seed AES-128-CBC 的真实密钥(bswap32 还原后)。
var mssdkAESKey = mustHex("b8d72ddec05142948bbf2dc81d63759c")

// mssdkAESIV 是 get_seed AES-128-CBC 的 IV。
var mssdkAESIV = mustHex("d6c3969582f9ac5313d39c180b54a2bc")

// MSSEncryptAES 用 mssdkAESKey/IV 做 AES-128-CBC + PKCS7 加密。
func MSSEncryptAES(plain []byte) []byte {
	// PKCS7 填充到 16 倍数
	padded := pkcs7Pad(plain, 16)
	block, _ := aes.NewCipher(mssdkAESKey)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, mssdkAESIV).CryptBlocks(ct, padded)
	return ct
}

// MSSDecryptAES 用 mssdkAESKey/IV 做 AES-128-CBC 解密,去 PKCS7。
func MSSDecryptAES(ct []byte) []byte {
	block, _ := aes.NewCipher(mssdkAESKey)
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, mssdkAESIV).CryptBlocks(pt, ct)
	return pkcs7Unpad(pt)
}

// pkcs7Unpad 去除 PKCS7 填充。pkcs7Pad 已在 xargus.go 定义。
func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > len(data) || pad > 16 {
		return data // 无效填充,原样返回
	}
	return data[:len(data)-pad]
}

// ---------- tea_key(get_seed 专用常量)----------

// mssdkTeaKey 是 get_seed 的 tea_key(hook 0x1140DC X0 实测,16B 完整常量)。
// 注意:这不是 report 协议的 tea_key(report 用 get_tea_report_key 派生)。
var mssdkTeaKey = mustHex("bd992378addecefa3031303234303430")

// ---------- XXTEA 单 block(已确认,Python 移植)----------

// xxTEAEncrypt 对齐 Python xx_tea_encrypt:单 8 字节 block,16 字节 key,loop 轮。
// delta = 0x9e3779b9。返回 8 字节密文。
func xxTEAEncrypt(data, key []byte, loop int) []byte {
	w10 := binary.BigEndian.Uint32(data[0:4])
	w9 := binary.BigEndian.Uint32(data[4:8])
	w11 := uint32(0)
	const delta = uint32(0x9e3779b9)
	for i := 0; i < loop; i++ {
		// 前半段
		w13 := w9 << 4
		w14 := w9 >> 5
		w15 := w13 | w14
		w13s := w13 & w14
		idx := w11 & 0x3
		w14k := binary.LittleEndian.Uint32(key[idx*4 : idx*4+4])
		w13r := w15 - w13s
		w15r := w13r ^ w9
		w13b2 := w15r + ((w13r & w9) << 1)
		w14sum := w11 + w14k
		w13c := (w14sum | w13b2) - (w14sum & w13b2)
		w15c := w13c ^ w10
		w10 = w13c | w10
		w11 = w11 + delta
		w10 = w10 << 1
		idx2 := (w11 >> 11) & 0b11
		w10 = w10 - w15c
		// 后半段
		w14k2 := binary.LittleEndian.Uint32(key[idx2*4 : idx2*4+4])
		w13a := (w10 >> 5) ^ (w10 << 4)
		w15a := w13a ^ w10
		w13b := (w13a | w10) << 1
		w14sum2 := w11 + w14k2
		w13final := ((w13b - w15a) & 0xFFFFFFFF) ^ w14sum2
		t2 := w13final ^ w9
		w9 = w13final & w9
		w9 = t2 + (w9 << 1)
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out[0:4], w10)
	binary.BigEndian.PutUint32(out[4:8], w9)
	return out
}

// xxTEADecrypt 是 xxTEAEncrypt 的严格逆(恒等式已数值验证)。
// 关键:w11 在前半段(idx=w11&3)用加delta前的值,后半段(idx2=(w11>>11)&3)用加delta后的值。
// 逆序:先逆后半段(用当前w11=末轮值),再 w11-=delta,再逆前半段。
func xxTEADecrypt(data, key []byte, loop int) []byte {
	w10 := binary.BigEndian.Uint32(data[0:4])
	w9 := binary.BigEndian.Uint32(data[4:8])
	const delta = uint32(0x9e3779b9)
	w11 := uint32(loop) * delta
	for i := 0; i < loop; i++ {
		// 逆后半段:w9_new = w9_old + w13final → w9_old = w9 - w13final
		idx2 := (w11 >> 11) & 0b11
		w14k := binary.LittleEndian.Uint32(key[idx2*4 : idx2*4+4])
		w13a := (w10 >> 5) ^ (w10 << 4)
		w15a := w13a ^ w10
		w13b := (w13a | w10) << 1
		w14sum := w11 + w14k
		w13final := ((w13b - w15a) & 0xFFFFFFFF) ^ w14sum
		w9 = w9 - w13final

		w11 = w11 - delta

		// 逆前半段:w10_new = w13c + w10_old → w10_old = w10 - w13c
		idx := w11 & 0x3
		w14k2 := binary.LittleEndian.Uint32(key[idx*4 : idx*4+4])
		w13e := w9 << 4
		w14e := w9 >> 5
		w15e := w13e | w14e
		w13s := w13e & w14e
		w13r := (w15e - w13s) & 0xFFFFFFFF
		w13b2 := (w13r ^ w9) + ((w13r & w9) << 1)
		w14sum2 := w11 + w14k2
		w13c := ((w14sum2 | w13b2) - (w14sum2 & w13b2)) & 0xFFFFFFFF
		w10 = w10 - w13c
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out[0:4], w10)
	binary.BigEndian.PutUint32(out[4:8], w9)
	return out
}

// ---------- custom_tea_encrypt / decrypt(已确认,Python 移植)----------

// customTEAEncrypt 对齐 Python custom_tea_encrypt:
//   - data 先 pad 到 8 倍数(零填充)
//   - 每 8B block:xor(xorKey) → xxTEAEncrypt → 累加;xorKey 更新为本块密文
//   - 末尾对最后一块密文再 xxTEAEncrypt 一次,累加
//
// xorKey: 8 字节(= random(4) ‖ 0x27042020)。
func customTEAEncrypt(data, teaKey, xorKey []byte, loop int) []byte {
	if pad := 8 - len(data)%8; pad < 8 {
		data = append(append([]byte{}, data...), make([]byte, pad)...)
	}
	var ret []byte
	var encrypted []byte
	for i := 0; i < len(data); i += 8 {
		raw := binary.BigEndian.Uint64(data[i : i+8])
		raw ^= binary.BigEndian.Uint64(xorKey)
		block := make([]byte, 8)
		binary.BigEndian.PutUint64(block, raw)
		encrypted = xxTEAEncrypt(block, teaKey, loop)
		ret = append(ret, encrypted...)
		xorKey = encrypted
	}
	// 末尾再加密一次最后一块
	encrypted = xxTEAEncrypt(encrypted, teaKey, loop)
	ret = append(ret, encrypted...)
	return ret
}

// customTEADecrypt 是 customTEAEncrypt 的逆。
// teaCT 长度 = (N+1)*8,N = data block 数。最后一块是末轮加密结果。
func customTEADecrypt(teaCT, teaKey, xorKey []byte, loop int) []byte {
	n := len(teaCT) / 8 // 含末轮块
	if n < 2 {
		return nil
	}
	// 末轮:teaCT[n-1] = xxTEA(teaCT[n-2]_real) → 恢复 enc[n-2]_real
	encRealLast := xxTEADecrypt(teaCT[(n-1)*8:n*8], teaKey, loop)
	// 倒序解密 data blocks i = n-2 .. 0
	decrypted := make([]byte, (n-1)*8)
	for i := n - 2; i >= 0; i-- {
		var encI []byte
		if i == n-2 {
			encI = encRealLast
		} else {
			encI = teaCT[i*8 : (i+1)*8]
		}
		raw := xxTEADecrypt(encI, teaKey, loop)
		// data[i] = raw ^ xorKey_prev;xorKey_prev = enc[i-1](i>0) 或初始 xorKey(i=0)
		var prevEnc []byte
		if i > 0 {
			prevEnc = teaCT[(i-1)*8 : i*8]
		} else {
			prevEnc = xorKey
		}
		rawU := binary.BigEndian.Uint64(raw)
		prevU := binary.BigEndian.Uint64(prevEnc)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, rawU^prevU)
		copy(decrypted[i*8:], b)
	}
	return decrypted
}

// ---------- flag 计算(已确认,Python 移植)----------

// getTeaLoopCount 从 4 字节 random(LE u32)算 TEA 轮数。
// 公式(汇编还原):loop = (random_LE % 5) * 8 + 32
func getTeaLoopCount(random []byte) int {
	v := binary.LittleEndian.Uint32(random)
	return int(v%5)*8 + 32
}

// headerTwoLen 对齐真机 ASM(sub_111C00 @ 0x111C4C-0x111C64):
//
//	v17 = 2*(v87 & 7) + (v87 ^ 7)     ; v87 = compressedLen
//	v18 = (v17 >= 0) ? v17 : v17+3    ; v17 始终 >=0,故 v18 = v17
//	v19 = v17 - (v18 & ~3)            ; = v17 - (v17 & ~3) = v17 & 3
//	                                   ; 但 v17 = 2*(L&7)+(L^7),展开后 v19 ∈ {1,2,3}
//
// 真机两抓包验证:L=134→1, L=84→3。
func headerTwoLen(compressedLen int) int {
	v87 := uint32(compressedLen)
	v17 := 2*(v87&7) + (v87 ^ 7)
	v18 := v17 // v17 >= 0 恒成立
	v19 := v17 - (v18 & 0xFFFFFFFC)
	return int(v19)
}

// calFlagOne 对齐真机 ASM(sub_111C00 @ 0x111C20):
//
//	*data_ptr = (random_addr & ~compressedLen & 0xF8) + compressedLen
//
// random_addr 是发送方本地 malloc 指针,服务端无法预知其值。
// 真机两抓包验证不变式:oneFlag % 8 == compressedLen % 8
//   - L=134 ra_low=0x80 → 0x86; 0x86%8=6, 134%8=6 ✓
//   - L=84  ra_low=0x?? → 0x64; 0x64%8=4, 84%8=4   ✓
//
// 服务端只校验 mod 8 对齐(决定 headerTwoLen),不校验 oneFlag 精确值。
func calFlagOne(compressedLen int) byte {
	var rb [4]byte
	rand.Read(rb[:])
	randomAddr := binary.LittleEndian.Uint32(rb[:])
	lenByte := uint32(compressedLen)
	return byte((randomAddr & ^lenByte & 0xF8) + lenByte)
}

// calFlagTwo 对齐真机 ASM(sub_111C00 @ 0x111C28-0x111C70):
//
//	v40 = (int)v41                      ; v41 = 数据缓冲区指针(random_addr_B)
//	memcpy(data+1, &v40, headerTwoLen)  ; headerTwo = 指针低字节(LE),随机
//
// 真机两抓包铁证:
//   - L=134 → headerTwoLen=1, headerTwo=0x80(指针低字节)
//   - L=84  → headerTwoLen=3, headerTwo=0x69b966(指针低3字节 LE)
//
// headerTwo 具体值 = 运行时 malloc 指针低字节,服务端无法预知 → 不校验具体值,
// 只校验长度(由 compressedLen 经 headerTwoLen 公式决定)。
//
// 旧实现误以为是「256字节表混淆」(flagTwoTable),那是签名 VM 内部用的,不是
// get_seed 传输层。本次 IDA 重逆(sub_111C00 反编译 0x111C28-0x111C70)纠正。
func calFlagTwo(compressedLen int) []byte {
	htLen := headerTwoLen(compressedLen)
	out := make([]byte, htLen)
	rand.Read(out) // 任意值;真机是指针低字节,等价于随机
	return out
}

// ---------- zlib 压缩(MSSDK 魔改 deflate,已逐字节复现)----------

// mssdkCompress 用 MSSDK 魔改 deflate 压缩,输出 = [长度前缀 4B LE] + [zlib 流]。
//
// MSSDK deflate 三个魔改点(逆向自 libmetasec_ov.so sub_E1FB1C / sub_129D38):
//  1. zlib header 硬编码 78 01(FLEVEL=0,不随 level 变化)
//  2. 块类型选择:符号数 >= 0x30(48) → dynamic Huffman,否则 fixed
//     (标准 zlib/Go flate 比较 dynamicSize < fixedSize)
//  3. Huffman 树 smaller tie-breaking:同频率时比较符号号(n<m),
//     标准 zlib 比较 depth(depth[n]<=depth[m])
//
// 实现用 fork 的 Go compress/flate(见 mflate 包),改了上述 3 点。
// 压缩 level = 6(Z_DEFAULT_COMPRESSION,真机实测 level=-1→6)。
func mssdkCompress(data []byte) ([]byte, error) {
	// 1. mflate 压缩(产出 raw deflate 流)
	var deflateBuf bytes.Buffer
	fw, err := mflate.NewWriter(&deflateBuf, 6)
	if err != nil {
		return nil, fmt.Errorf("mssdk mflate level: %w", err)
	}
	if _, err := fw.Write(data); err != nil {
		return nil, fmt.Errorf("mssdk mflate write: %w", err)
	}
	if err := fw.Close(); err != nil {
		return nil, fmt.Errorf("mssdk mflate close: %w", err)
	}

	// 2. 组装 zlib 流:header(78 01) + deflate + adler32
	zlibStream := make([]byte, 2+deflateBuf.Len()+4)
	zlibStream[0] = 0x78 // CMF: CM=8(deflate), CINFO=7(32K window)
	zlibStream[1] = 0x01 // FLG: FCHECK=1((CMF*256+FLG)%31==0), FDICT=0, FLEVEL=0
	copy(zlibStream[2:2+deflateBuf.Len()], deflateBuf.Bytes())
	// adler32(标准,未改):big-endian
	adler := adler32(data)
	binary.BigEndian.PutUint32(zlibStream[2+deflateBuf.Len():], adler)

	// 3. 前置 4B 长度(LE)= 原始数据长度
	out := make([]byte, 4+len(zlibStream))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(data)))
	copy(out[4:], zlibStream)
	return out, nil
}

// MSSDKCompressExported 是 mssdkCompress 的导出版本,供测试用。
func MSSDKCompressExported(data []byte) ([]byte, error) {
	return mssdkCompress(data)
}

// adler32 计算 Adler-32 校验和(标准 zlib 算法,MSSDK 未改)。
func adler32(data []byte) uint32 {
	const mod = 65521
	var a, b uint32 = 1, 0
	for _, c := range data {
		a = (a + uint32(c)) % mod
		b = (b + a) % mod
	}
	return (b << 16) | a
}

// mssdkDecompress 是 mssdkCompress 的逆:去 4B 长度前缀,zlib 解压。
func mssdkDecompress(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("mssdk decompress: data too short")
	}
	// 找 zlib magic(78 01 / 78 9c / 78 da)确定流起点
	start := 4
	if data[4] != 0x78 {
		// 无长度前缀,直接是 zlib 流
		start = 0
	}
	r, err := zlib.NewReader(bytes.NewReader(data[start:]))
	if err != nil {
		return nil, fmt.Errorf("mssdk zlib decompress: %w", err)
	}
	defer r.Close()
	// 读全部解压数据。zlib 流末尾有 4B adler32 校验,真机响应偶有校验不匹配
	// (flate: corrupt input before offset N),但解压数据本身已完整可用 ——
	// 只要 buffer 非空就返回,不因末尾校验失败丢弃已解压内容。
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil && buf.Len() == 0 {
		return nil, fmt.Errorf("mssdk zlib read: %w", err)
	}
	return buf.Bytes(), nil
}

// ---------- EncodeRequest / DecryptField4 总入口 ----------

// MSSSeedSDKVersion 是 get_seed body field-4 的 sdk_version 短版(frida 实拍)。
const MSSSeedSDKVersion = "v05.00.05"

// MSSEncodeRequest 对齐 Python encode_request,组装完整加密链。
// 输入:MSSeedRequest protobuf(明文)。
// 输出:AES-128-CBC 密文(= get_seed POST body 的 field-4)。
func MSSEncodeRequest(plaintext []byte) ([]byte, error) {
	// 1. zlib 压缩
	compressed, err := mssdkCompress(plaintext)
	if err != nil {
		return nil, err
	}

	// 2. flag 头部
	//    oneFlag / headerTwo 都含运行时随机量(malloc 指针低字节),
	//    服务端只校验长度对齐(headerTwoLen = f(compressedLen)),不校验具体值。
	oneFlag := calFlagOne(len(compressed))
	headerTwo := calFlagTwo(len(compressed))

	// 3. data = one_flag + header_two + compressed
	data := append([]byte{oneFlag}, headerTwo...)
	data = append(data, compressed...)

	// 4. customTEA 加密
	random := make([]byte, 4)
	rand.Read(random)
	xorKey := append(random, 0x27, 0x04, 0x20, 0x20)
	loop := getTeaLoopCount(random)
	teaCT := customTEAEncrypt(data, mssdkTeaKey, xorKey, loop)

	// 5. first_flag:在密文前插 1B。
	//   真机 ASM(sub_111C00 @ 0x112290-0x1122b4)还原:
	//     *v41 = 3; *v41 = (*v41 | v41[1]) - (*v41 & v41[1])
	//   (a|b)-(a&b) == a^b,所以 first_flag = teaCT[0] ^ 3。
	//   真机验证:teaCT[0]=0xeb → 0xeb^3 = 0xe8 = 实测 pt[0]。
	//   (旧实现误用 |3,会得 0xeb≠0xe8,服务端拒绝。)
	firstFlag := teaCT[0] ^ 3
	teaCT = append([]byte{firstFlag}, teaCT...)

	// 6. raw_aes = first_flag + teaCT + random(4)
	rawAES := append(teaCT, random...)

	// 7. AES-128-CBC
	return MSSEncryptAES(rawAES), nil
}

// MSSDecryptField 是 MSSEncodeRequest 的逆:密文 → 原始 protobuf。
// 请求(field-4)和响应(field-6)共用同一解密链,只是 zlib FLEVEL 不同:
//   - 请求用 78 01(MSSDK 魔改,FLEVEL=0)
//   - 响应用 78 da(标准,FLEVEL=2)
//
// mssdkDecompress 内部用标准 zlib reader,自动适配所有 zlib magic。
func MSSDecryptField(ct []byte) ([]byte, error) {
	// 1. AES-128-CBC 解密
	rawAES := MSSDecryptAES(ct)
	if len(rawAES) < 5 {
		return nil, fmt.Errorf("mssdk decrypt: rawAES too short (%d)", len(rawAES))
	}

	// 2. 切分:first_flag(1) + teaCT + random(4)
	//    teaCT 长度 = len(rawAES) - 5
	random := rawAES[len(rawAES)-4:]
	teaCT := rawAES[1 : len(rawAES)-4]

	// 3. customTEA 解密
	xorKey := append(random, 0x27, 0x04, 0x20, 0x20)
	loop := getTeaLoopCount(random)
	decrypted := customTEADecrypt(teaCT, mssdkTeaKey, xorKey, loop)
	if decrypted == nil {
		return nil, fmt.Errorf("mssdk decrypt: customTEA decrypt failed")
	}

	// 4. 去 header,找 zlib magic 定位压缩流
	//    decrypted = one_flag + header_two(1-3) + [len前缀4] + zlib流 + padding
	//    zlib magic = 0x78 + FLEVEL(0x01 请求 / 0x9c / 0xda 响应)
	zlibIdx := findZlibMagic(decrypted)
	if zlibIdx < 0 {
		return nil, fmt.Errorf("mssdk decrypt: zlib magic not found")
	}
	// 前面应有 4B 长度前缀
	start := zlibIdx
	if zlibIdx >= 4 {
		start = zlibIdx - 4
	}

	// 5. zlib 解压
	return mssdkDecompress(decrypted[start:])
}

// MSSDecryptField4 是 MSSDecryptField 的旧名别名(向后兼容)。
func MSSDecryptField4(ct []byte) ([]byte, error) { return MSSDecryptField(ct) }

// findZlibMagic 在 data 中查找 zlib 流起始(0x78 后跟合法 FLEVEL/FCHECK)。
// zlib header: CMF=0x78(CM=8,CINFO=7), FLG 满足 (CMF*256+FLG)%31==0。
// 常见: 78 01 / 78 9c / 78 da。这里只匹配 0x78 前缀 + 校验 %31。
func findZlibMagic(data []byte) int {
	for i := 0; i < len(data)-1; i++ {
		if data[i] == 0x78 {
			flg := data[i+1]
			if (0x78*256+int(flg))%31 == 0 && flg&0x20 == 0 { // FDICT=0
				return i
			}
		}
	}
	return -1
}

// ---------- helpers ----------

func mustHex(s string) []byte {
	clean := make([]byte, 0, len(s)/2)
	for _, c := range []byte(s) {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			clean = append(clean, c)
		}
	}
	b := make([]byte, len(clean)/2)
	for i := range b {
		hi := fromHexNibble(clean[i*2])
		lo := fromHexNibble(clean[i*2+1])
		b[i] = hi<<4 | lo
	}
	return b
}

func fromHexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
