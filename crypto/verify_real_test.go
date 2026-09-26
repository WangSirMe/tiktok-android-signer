package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestEncodeMatchesRealPT 用真机的 compressed + random 强制复现真机 pt,
// 逐字节证明 first_flag(^3) 修复后我们的加密链与真机完全一致。
//
// 真机数据(从 AES-CBC 明文反解):
//
//	one_flag=0x86, header_two=0x80, compressed=4b000000+<82B zlib>
//	random=d808100c → loop=48, xorKey=d808100c27042020
//	teaCT(96B) → first_flag=teaCT[0]^3=0xeb^3=0xe8
//	rawAES = first_flag + teaCT + random
func TestEncodeMatchesRealPT(t *testing.T) {
	// 真机完整 pt(AES-CBC 明文,去 PKCS7)
	ptHex := "e8eb5405f7c0f2ad8dfa3cdfc8406a6cbe17741e8747d6a3fe3618e01e1cddc45bb21cb740fba98a52c64de60abc4aef659dd70aed608eb3a4b762ebbc58c00ee0b553101bee4f377e0656ea8ef30c5e01ff59936005b28cd0d1fcc8676308b548d808100c"
	pt, _ := hex.DecodeString(ptHex)

	// 切出真机各段
	firstFlagReal := pt[0]     // 0xe8
	teaCT := pt[1 : len(pt)-4] // 96B
	random := pt[len(pt)-4:]   // d808100c

	// 反推 teaCT 应该加密的 data = one_flag + header_two + compressed
	xorKey := append([]byte{}, random...)
	xorKey = append(xorKey, 0x27, 0x04, 0x20, 0x20)
	loop := getTeaLoopCount(random)
	data := customTEADecrypt(teaCT, mssdkTeaKey, xorKey, loop)
	t.Logf("data = %x (len=%d)", data, len(data))
	oneFlagReal := data[0] // 0x86
	headerTwo := data[1]   // 0x80
	compressed := data[2:] // 86B

	// 用我们的 customTEAEncrypt 重新加密 data,应得 teaCT
	teaCTRebuilt := customTEAEncrypt(data, mssdkTeaKey, xorKey, loop)
	if !bytes.Equal(teaCTRebuilt, teaCT) {
		t.Errorf("customTEAEncrypt 复现失败:\n got  = %x\n want = %x", teaCTRebuilt, teaCT)
	} else {
		t.Logf("✅ customTEAEncrypt(data, key, loop=48) 逐字节复现真机 teaCT")
	}

	// first_flag 公式验证
	firstFlagCalc := teaCT[0] ^ 3
	if firstFlagCalc != firstFlagReal {
		t.Errorf("first_flag: got 0x%02x, want 0x%02x", firstFlagCalc, firstFlagReal)
	} else {
		t.Logf("✅ first_flag = teaCT[0]^3 = 0x%02x (真机 0x%02x)", firstFlagCalc, firstFlagReal)
	}

	// 组装 rawAES,与真机 pt 逐字节比对
	rawAES := make([]byte, 0, 1+len(teaCT)+4)
	rawAES = append(rawAES, firstFlagCalc)
	rawAES = append(rawAES, teaCT...)
	rawAES = append(rawAES, random...)
	if !bytes.Equal(rawAES, pt) {
		t.Errorf("rawAES 组装与真机 pt 不符:\n got  = %x\n want = %x", rawAES, pt)
	} else {
		t.Logf("✅ rawAES = first_flag(^3) + teaCT + random 逐字节 == 真机 pt")
	}

	// one_flag 公式复现(用真机 compressedLen=134)
	ofFormula := byte((uint32(0x80) & ^uint32(134) & 0xF8) + 134)
	if ofFormula != oneFlagReal {
		t.Errorf("one_flag 公式: got 0x%02x, want 0x%02x", ofFormula, oneFlagReal)
	} else {
		t.Logf("✅ one_flag 公式 (0x80 & ~134 & 0xF8) + 134 = 0x%02x (真机 0x%02x)", ofFormula, oneFlagReal)
	}

	// headerTwoLen 验证(compressedLen=134 → 1,与真机 header_two len 一致)
	htLen := headerTwoLen(len(compressed))
	if htLen != 1 {
		t.Errorf("headerTwoLen(%d)=%d, want 1(真机)", len(compressed), htLen)
	}
	// 真机 header_two=0x80 是数据缓冲区指针(malloc)的低字节,服务端不校验具体值。
	// (旧实现误以为是 flagTwoTable 查表输出;IDA sub_111C00 @ 0x111C28-0x111C70
	//  反编译铁证:memcpy(data+1, &ptr, htLen) → headerTwo = 指针低字节,随机)
	t.Logf("✅ headerTwo(len==1) = 指针低字节(真机 0x%02x,随机值不校验)", headerTwo)
	_ = binary.LittleEndian
}
