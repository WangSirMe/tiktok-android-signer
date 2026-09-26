package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestCaptureE2EField4 用真机完整抓包(131B body)做端到端对拍:
//
// 解密真机 body field-4 → 取出明文 protobuf(75B)→ 用真机全部固定参数
// (oneFlag/headerTwo/random)重新走加密链 → 逐字节比对真机 field-4。
//
// 真机抓包(mssdk22-normal-alisg /ms/get_seed, 33.2.5):
//
//	body(131B) = outer_protobuf {
//	  field1 = 0x40400844 (SDK magic)
//	  field2 = 2
//	  field3 = 4
//	  field4 = AES 密文(112B) → rawAES(101B) = firstFlag + teaCT(96) + random(4)
//	}
//
//	明文(75B) = MSSeedRequest{ session, deviceid, os="android", sdk="v05.00.05" }
//	压缩(84B) = [4B len LE=0x4b] + [zlib 80B]
//	oneFlag=0x64, headerTwo=69b966(len3, 指针低字节随机), random=d8e89f69
//
// 本测试证明:压缩/TEA/firstFlag/AES 全链路逐字节对齐真机;
// 仅 oneFlag/headerTwo/random 是运行时随机量(服务端不校验具体值,见 TestCalFlagOneFormula)。
func TestCaptureE2EField4(t *testing.T) {
	bodyHex := "08c490808204100218042270f141e3906512ae68133d61f594ce3cd894b44903befd" +
		"0ab0b33117099f76aff3e3e724fa34c651e4cfe39325db23209cd9c89e17c934993b" +
		"c20ff0eafbd774da37163c5abfa4f6a8a6e0f94498741cf2e95e277fb40053eb637" +
		"5d14e7ea363d3ee1ff4a86179f9db475f016654a85b4428dee2898dec67"
	body, _ := hex.DecodeString(bodyHex)

	// --- 1. 解析外层 protobuf,取 field-4 ---
	field4 := parseOuterField4(t, body)
	if len(field4) != 112 {
		t.Fatalf("field4 len=%d, want 112", len(field4))
	}

	// --- 2. AES 解密 → rawAES ---
	rawAES := MSSDecryptAES(field4)
	if len(rawAES) != 101 {
		t.Fatalf("rawAES len=%d, want 101", len(rawAES))
	}
	firstFlagReal := rawAES[0]
	random := rawAES[len(rawAES)-4:]
	teaCTReal := rawAES[1 : len(rawAES)-4]

	// --- 3. customTEA 解密 → data ---
	xorKey := append(append([]byte{}, random...), 0x27, 0x04, 0x20, 0x20)
	loop := getTeaLoopCount(random)
	data := customTEADecrypt(teaCTReal, mssdkTeaKey, xorKey, loop)
	if len(data) != 88 {
		t.Fatalf("data len=%d, want 88", len(data))
	}
	oneFlagReal := data[0]
	headerTwoReal := data[1:4] // headerTwoLen(84)=3
	compressedReal := data[4:] // 84B = 4B len + 80B zlib

	// --- 4. 解压拿明文 ---
	plain, err := mssdkDecompress(compressedReal)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Contains(plain, []byte("android")) || !bytes.Contains(plain, []byte("v05.00.05")) {
		t.Fatalf("plaintext missing fields: %x", plain)
	}

	// --- 5. 压缩对拍:明文 → mssdkCompress 应逐字节 == 真机 compressed ---
	gotComp, err := mssdkCompress(plain)
	if err != nil {
		t.Fatalf("mssdkCompress: %v", err)
	}
	if !bytes.Equal(gotComp, compressedReal) {
		t.Errorf("❌ 压缩不匹配:\n got  (%d)=%x\n want (%d)=%x",
			len(gotComp), gotComp, len(compressedReal), compressedReal)
	} else {
		t.Logf("✅ mssdkCompress(明文) 逐字节 == 真机 compressed(%dB)", len(compressedReal))
	}

	// --- 6. TEA 重加密:用真机 data 重新 customTEAEncrypt 应得真机 teaCT ---
	dataReal := append([]byte{oneFlagReal}, headerTwoReal...)
	dataReal = append(dataReal, compressedReal...)
	teaCTRebuilt := customTEAEncrypt(dataReal, mssdkTeaKey, xorKey, loop)
	if !bytes.Equal(teaCTRebuilt, teaCTReal) {
		t.Errorf("❌ TEA 不匹配:\n got  =%x\n want =%x", teaCTRebuilt, teaCTReal)
	} else {
		t.Logf("✅ customTEAEncrypt(真机data) 逐字节 == 真机 teaCT(%dB)", len(teaCTReal))
	}

	// --- 7. firstFlag = teaCT[0]^3 ---
	firstFlagCalc := teaCTReal[0] ^ 3
	if firstFlagCalc != firstFlagReal {
		t.Errorf("firstFlag: 0x%02x != 真机 0x%02x", firstFlagCalc, firstFlagReal)
	} else {
		t.Logf("✅ firstFlag = teaCT[0]^3 = 0x%02x", firstFlagCalc)
	}

	// --- 8. rawAES 组装 + AES 加密 → 应逐字节 == 真机 field-4 ---
	rawAESRebuilt := make([]byte, 0, 1+len(teaCTReal)+4)
	rawAESRebuilt = append(rawAESRebuilt, firstFlagCalc)
	rawAESRebuilt = append(rawAESRebuilt, teaCTReal...)
	rawAESRebuilt = append(rawAESRebuilt, random...)
	if !bytes.Equal(rawAESRebuilt, rawAES) {
		t.Errorf("❌ rawAES 组装不匹配")
	} else {
		t.Logf("✅ rawAES = firstFlag + teaCT + random 逐字节 == 真机")
	}
	field4Rebuilt := MSSEncryptAES(rawAESRebuilt)
	if !bytes.Equal(field4Rebuilt, field4) {
		t.Errorf("❌ AES field-4 不匹配:\n got  =%x\n want =%x", field4Rebuilt, field4)
	} else {
		t.Logf("✅ MSSEncryptAES(rawAES) 逐字节 == 真机 field-4(%dB)", len(field4))
	}

	// --- 9. 外层 body 组装 ---
	//    真机 body 末尾还有 field-5(varint,传输层字段,非加密链一部分)。
	//    加密链只关心 field-1(magic)+ field-4(密文);field-5 服务端不校验。
	//    这里用真机 field-5 值验证重组结构正确。
	field5Real := uint64(3568071504222)
	bodyRebuilt := buildOuterBody(field4Rebuilt, field5Real)
	if !bytes.Equal(bodyRebuilt, body) {
		t.Errorf("❌ body 不匹配:\n got  =%x\n want =%x", bodyRebuilt, body)
	} else {
		t.Logf("✅ 完整 body(%dB) 逐字节 == 真机抓包!", len(body))
	}

	// --- 10. headerTwoLen 公式验证 ---
	if got := headerTwoLen(len(compressedReal)); got != len(headerTwoReal) {
		t.Errorf("headerTwoLen(%d)=%d, want %d", len(compressedReal), got, len(headerTwoReal))
	} else {
		t.Logf("✅ headerTwoLen(%d)=%d(真机 headerTwo %dB,值=指针低字节随机不校验)",
			len(compressedReal), got, len(headerTwoReal))
	}
}

// parseOuterField4 解析外层 protobuf 取 field-4 bytes。
func parseOuterField4(t *testing.T, body []byte) []byte {
	t.Helper()
	i := 0
	for i < len(body) {
		tag := body[i]
		i++
		fn := tag >> 3
		wt := tag & 7
		if wt == 0 {
			_, n := readVarintX(body[i:])
			i += n
		} else if wt == 2 {
			ln, n := readVarintX(body[i:])
			i += n
			val := body[i : i+int(ln)]
			i += int(ln)
			if fn == 4 {
				return val
			}
		} else {
			t.Fatalf("unexpected wire %d at %d", wt, i)
		}
	}
	return nil
}

// buildOuterBody 用真机 field1/2/3/5 重组外层 body。
func buildOuterBody(field4 []byte, field5 uint64) []byte {
	var buf []byte
	// field1 = 0x40400844 (varint)
	buf = appendVarint(buf, 1<<3, 0x40400844)
	// field2 = 2
	buf = appendVarint(buf, 2<<3, 2)
	// field3 = 4
	buf = appendVarint(buf, 3<<3, 4)
	// field4 = bytes
	buf = append(buf, 4<<3|2)
	buf = appendVarint(buf, 0, uint64(len(field4)))
	buf = append(buf, field4...)
	// field5 = varint(传输层字段,非加密链)
	buf = appendVarint(buf, 5<<3, field5)
	return buf
}

func appendVarint(buf []byte, tag, v uint64) []byte {
	if tag != 0 {
		buf = append(buf, byte(tag))
	}
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func readVarintX(b []byte) (uint64, int) {
	var v uint64
	var s uint
	for i, c := range b {
		v |= uint64(c&0x7f) << s
		if c < 0x80 {
			return v, i + 1
		}
		s += 7
	}
	return v, len(b)
}

var _ = binary.LittleEndian
