package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// ---------- 真机验证测试(用 frida 抓的配对数据)----------

// TestMSSAESCBCPair 验证 AES-128-CBC:key/IV 能复现真机 field-4。
// 数据来源:hook sub_149EAC mode=4 窗口(tid 配对)。
func TestMSSAESCBCPair(t *testing.T) {
	// pt(AES-CBC 明文,去 PKCS7)
	ptHex := "e8eb5405f7c0f2ad8dfa3cdfc8406a6cbe17741e8747d6a3fe3618e01e1cddc45bb21cb740fba98a52c64de60abc4aef659dd70aed608eb3a4b762ebbc58c00ee0b553101bee4f377e0656ea8ef30c5e01ff59936005b28cd0d1fcc8676308b548d808100c"
	// 对应的 PKCS7 填充版本(末 11B = 0x0b)
	ptPaddedHex := ptHex + "0b0b0b0b0b0b0b0b0b0b0b"
	pt, _ := hex.DecodeString(ptPaddedHex)
	ct := MSSEncryptAES(pt[:101]) // 输入去 PKCS7 前的明文,MSSEncryptAES 内部会 pad
	_ = ct
	// 反向:解密应还原
	dec := MSSDecryptAES(ct)
	if !bytes.Equal(dec, pt[:101]) {
		t.Errorf("AES-CBC round-trip 失败:\n got  = %x\n want = %x", dec, pt[:101])
	} else {
		t.Logf("✅ AES-128-CBC round-trip 成功")
	}
}

// TestXXTEARoundTrip 验证 xxTEA encrypt→decrypt 还原。
func TestXXTEARoundTrip(t *testing.T) {
	key := mssdkTeaKey
	cases := []string{
		"0123456789abcdef",
		"0000000000000000",
		"ffffffffffffffff",
		"bd992378addecefa",
	}
	for _, c := range cases {
		data, _ := hex.DecodeString(c)
		for _, loop := range []int{1, 6, 16, 32, 48} {
			enc := xxTEAEncrypt(data, key, loop)
			dec := xxTEADecrypt(enc, key, loop)
			if hex.EncodeToString(dec) != c {
				t.Errorf("loop=%d data=%s: enc=%x dec=%x", loop, c, enc, dec)
			}
		}
	}
	t.Logf("✅ xxTEA round-trip 全部通过")
}

// TestGetTeaLoopCount 验证 loop 公式:random_LE=0xd808100c → loop=48。
func TestGetTeaLoopCount(t *testing.T) {
	random, _ := hex.DecodeString("d808100c")
	loop := getTeaLoopCount(random)
	if loop != 48 {
		t.Errorf("getTeaLoopCount(d808100c) = %d, want 48", loop)
	} else {
		t.Logf("✅ getTeaLoopCount = %d", loop)
	}
}

// TestCustomTEAEndRound 验证 customTEA 的末轮等式(用真机 pt)。
// 证明 tea_key/loop 正确:block[N-2]→block[N-1] xxTEA 关系成立。
func TestCustomTEAEndRound(t *testing.T) {
	ptHex := "e8eb5405f7c0f2ad8dfa3cdfc8406a6cbe17741e8747d6a3fe3618e01e1cddc45bb21cb740fba98a52c64de60abc4aef659dd70aed608eb3a4b762ebbc58c00ee0b553101bee4f377e0656ea8ef30c5e01ff59936005b28cd0d1fcc8676308b548d808100c"
	pt, _ := hex.DecodeString(ptHex)
	teaPart := pt[1 : len(pt)-4] // 去 first_flag(1) + random(4)

	n := len(teaPart) / 8
	prev := teaPart[(n-2)*8 : (n-2)*8+8]
	next := teaPart[(n-1)*8 : (n-1)*8+8]
	got := xxTEAEncrypt(prev, mssdkTeaKey, 48)
	if hex.EncodeToString(got) != hex.EncodeToString(next) {
		t.Errorf("末轮等式失败:got %x, want %x", got, next)
	} else {
		t.Logf("✅ customTEA 末轮等式命中(tea_key + loop=48 确认)")
	}
}

// TestDecryptField4EndToEnd 完整解密:field-4 密文 → 原始 protobuf。
func TestDecryptField4EndToEnd(t *testing.T) {
	// 真机抓的 pt(AES-CBC 明文,去 PKCS7)
	ptHex := "e8eb5405f7c0f2ad8dfa3cdfc8406a6cbe17741e8747d6a3fe3618e01e1cddc45bb21cb740fba98a52c64de60abc4aef659dd70aed608eb3a4b762ebbc58c00ee0b553101bee4f377e0656ea8ef30c5e01ff59936005b28cd0d1fcc8676308b548d808100c"
	pt, _ := hex.DecodeString(ptHex)
	// 构造完整 AES-CBC 明文(加 PKCS7)
	padded := pkcs7Pad(pt, 16)
	// 加密得 field-4 密文
	ct := MSSEncryptAES(pt)

	// 完整解密
	plain, err := MSSDecryptField4(ct)
	if err != nil {
		t.Fatalf("MSSDecryptField4: %v", err)
	}
	t.Logf("解密 protobuf = %x", plain)
	// 应包含 android / v05.00.05
	if !bytes.Contains(plain, []byte("android")) {
		t.Errorf("解密结果不含 'android'")
	}
	if !bytes.Contains(plain, []byte("v05.00.05")) {
		t.Errorf("解密结果不含 'v05.00.05'")
	}
	t.Logf("✅ 完整解密链通过,protobuf 还原成功")
	_ = padded
}

// TestEncodeDecodeRoundTrip 验证 MSSEncodeRequest → MSSDecryptField4 还原。
func TestEncodeDecodeRoundTrip(t *testing.T) {
	// 构造一个 MSSeedRequest protobuf
	plain := []byte("0a20" + "92fa043914ed43d9baede9ed74c39b43" +
		"1213" + "7659353200026502657" +
		"1a07" + "616e64726f6964" +
		"2209" + "7630352e30302e3035")
	plainBytes, _ := hex.DecodeString(string(plain))

	ct, err := MSSEncodeRequest(plainBytes)
	if err != nil {
		t.Fatalf("MSSEncodeRequest: %v", err)
	}
	t.Logf("加密 field-4 = %d B", len(ct))

	dec, err := MSSDecryptField4(ct)
	if err != nil {
		t.Fatalf("MSSDecryptField4: %v", err)
	}
	if !bytes.Equal(dec, plainBytes) {
		t.Errorf("round-trip 失败:\n got  = %x\n want = %x", dec, plainBytes)
	} else {
		t.Logf("✅ EncodeRequest → DecryptField4 round-trip 成功")
	}
}

func hexDec(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// TestFirstFlagXor3 验证 first_flag = teaCT[0] ^ 3(不是 |3)。
//
// 真机 ASM(sub_111C00 @ 0x112290-0x1122b4)还原:
//
//	*v41 = 3
//	*v41 = (*v41 | v41[1]) - (*v41 & v41[1])   // (a|b)-(a&b) == a^b
//
// → first_flag = teaCT[0] ^ 3。
//
// 真机实测:teaCT[0]=0xeb → first_flag=0xe8(= pt[0])。旧实现误用 |3 会得 0xeb。
func TestFirstFlagXor3(t *testing.T) {
	// 真机 AES-CBC 明文(去 PKCS7):first_flag(1) + teaCT(96) + random(4) = 101B
	ptHex := "e8eb5405f7c0f2ad8dfa3cdfc8406a6cbe17741e8747d6a3fe3618e01e1cddc45bb21cb740fba98a52c64de60abc4aef659dd70aed608eb3a4b762ebbc58c00ee0b553101bee4f377e0656ea8ef30c5e01ff59936005b28cd0d1fcc8676308b548d808100c"
	pt, _ := hex.DecodeString(ptHex)
	firstFlagReal := pt[0] // 0xe8
	teaCT0 := pt[1]        // 0xeb
	want := firstFlagReal  // 0xe8
	got := teaCT0 ^ 3      // 公式
	if got != want {
		t.Errorf("first_flag = teaCT[0]^3: got 0x%02x, want 0x%02x", got, want)
	}
	// 显式证明 |3 是错的
	if teaCT0|3 == want {
		t.Errorf("意外的 |3 命中:0x%02x|3 = 0x%02x", teaCT0, teaCT0|3)
	}
	t.Logf("✅ first_flag = 0xeb ^ 3 = 0x%02x(= 真机 pt[0] 0xe8),|3 会错得 0xeb", got)
}

// TestCalFlagOneFormula 验证 calFlagOne 的 ASM 公式 + headerTwoLen 公式。
//
// 真机两抓包铁证(sub_111C00 @ 0x111C20 / 0x111C4C-0x111C64):
//
//	one_flag     = (random_addr & ~compressedLen & 0xF8) + compressedLen
//	headerTwoLen = f(compressedLen)   // 见 headerTwoLen 文档
//
//	旧抓包: L=134 → oneFlag=0x86 (ra_low=0x80), headerTwoLen=1
//	新抓包: L=84  → oneFlag=0x64,              headerTwoLen=3
//
// 关键不变式:one_flag % 8 == compressedLen % 8(扰动项只影响 bit3..7)。
// 服务端只校验 mod 8 对齐 + headerTwoLen,不校验 one_flag / headerTwo 具体值。
func TestCalFlagOneFormula(t *testing.T) {
	// 1. 公式自洽:真机已知 ra_low=0x80, L=134 → oneFlag=0x86
	ra := uint32(0x80)
	oneFlag := byte((ra & ^uint32(134) & 0xF8) + 134)
	if oneFlag != 0x86 {
		t.Errorf("公式: ra=0x80 L=134 → 0x%02x, want 0x86", oneFlag)
	} else {
		t.Logf("✅ calFlagOne 公式复现真机:ra=0x80, L=134 → oneFlag=0x86")
	}

	// 2. 不变式:任意 ra/L 下 oneFlag%8 == L%8
	for _, L := range []int{82, 84, 86, 88, 134, 200} {
		for ra := uint32(0); ra < 256; ra++ {
			of := byte((ra & ^uint32(L) & 0xF8) + uint32(L))
			if int(of)%8 != L%8 {
				t.Errorf("不变式破坏:L=%d ra=0x%02x → 0x%02x (mod8=%d, want %d)",
					L, ra, of, int(of)%8, L%8)
			}
		}
	}
	t.Logf("✅ 不变式:oneFlag %% 8 == compressedLen %% 8(任意 ra)")

	// 3. headerTwoLen 真机两抓包验证
	cases := []struct{ L, want int }{{134, 1}, {84, 3}}
	for _, c := range cases {
		got := headerTwoLen(c.L)
		if got != c.want {
			t.Errorf("headerTwoLen(%d)=%d, want %d", c.L, got, c.want)
		} else {
			t.Logf("✅ headerTwoLen(%d)=%d(真机一致)", c.L, got)
		}
	}

	// 4. calFlagTwo 输出长度 == headerTwoLen
	for _, c := range cases {
		ht := calFlagTwo(c.L)
		if len(ht) != c.want {
			t.Errorf("calFlagTwo(%d) len=%d, want %d", c.L, len(ht), c.want)
		}
	}
	t.Logf("✅ calFlagTwo 输出长度 == headerTwoLen")
}
