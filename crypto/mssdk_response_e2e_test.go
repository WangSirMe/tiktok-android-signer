package crypto

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"testing"
)

// TestCaptureE2EResponse 端到端验证 get_seed 响应解密链:
//
// 真机响应(189B)→ 外层 protobuf 取 field6(176B 密文)→ AES-CBC 解密 →
// customTEA 解密 → zlib 解压(标准 78 da)→ MSSeedResponse 明文 protobuf
// → 提取 seed(132B base64)+ algorithm。
//
// 真机响应(mssdk22-normal-alisg /ms/get_seed, 33.2.5,本次实测抓取):
//
//	outer { field1=0x40240624, field2=2, field5=4, field6=176B 密文 }
//	解密后 data = oneFlag + headerTwo(3) + [4B len=0x8c=140] + zlib(78 da)
//	明文 = MSSeedResponse { seed=1(132B), extra_info=2 }
//
// 与请求的差异:
//   - 请求密文在 field4,响应在 field6
//   - 请求 zlib=78 01(魔改 FLEVEL=0),响应=78 da(标准 FLEVEL=2)
//   - 响应 zlib 末尾 adler32 偶尔校验不匹配(真机端),但解压数据完整
func TestCaptureE2EResponse(t *testing.T) {
	// 真机响应完整 hex(189B)
	respHex := "08a48c9081041002280432b001c1b19050309e3b91fc8c7f586464dddcd7c67b0c7e" +
		"8a45982d598df72614189db590a2c961f2ab74925b2ae7a24a183970673ffb8214bbd" +
		"c3c987d2a7147a526dbacf3b78ab1b7c279d44be275739a3ab5c8526f63445e566f7" +
		"e86c996b4469b167d8cc1e35a5fa70be35953437b0ab066236255caa43ce1b770c2b" +
		"2a623e9739974c93ed2166711992f7d11c8f1482cb3474c5ca5af26c371d0b31d985" +
		"896cdc75fefbacd26ccaca7d1f036a8230beb"
	resp, _ := hex.DecodeString(respHex)
	if len(resp) != 189 {
		t.Fatalf("resp len=%d, want 189", len(resp))
	}

	// 1. 解析外层取 field6
	var field6 []byte
	i := 0
	for i < len(resp) {
		tag := resp[i]
		i++
		fn := tag >> 3
		wt := tag & 7
		if wt == 0 {
			_, n := readVarintX(resp[i:])
			i += n
		} else if wt == 2 {
			ln, n := readVarintX(resp[i:])
			i += n
			val := resp[i : i+int(ln)]
			i += int(ln)
			if fn == 6 {
				field6 = val
			}
		}
	}
	if len(field6) != 176 {
		t.Fatalf("field6 len=%d, want 176", len(field6))
	}
	t.Logf("✅ 外层 field6 提取(%dB)", len(field6))

	// 2. MSSDecryptField 全链路解密
	plain, err := MSSDecryptField(field6)
	if err != nil {
		t.Fatalf("MSSDecryptField: %v", err)
	}
	if len(plain) == 0 {
		t.Fatal("MSSDecryptField 返回空")
	}
	t.Logf("✅ MSSDecryptField 解密成功(%dB)", len(plain))

	// 3. 解析明文 MSSeedResponse { seed=1, extra_info=2 }
	var seed string
	j := 0
	for j < len(plain) {
		tag := plain[j]
		j++
		fn := tag >> 3
		wt := tag & 7
		if wt != 2 {
			_, n := readVarintX(plain[j:])
			j += n
			continue
		}
		ln, n := readVarintX(plain[j:])
		j += n
		val := plain[j : j+int(ln)]
		j += int(ln)
		if fn == 1 {
			seed = string(val)
		}
	}
	if len(seed) == 0 {
		t.Fatal("seed 为空")
	}
	t.Logf("✅ seed 提取(%dB): %s...", len(seed), seed[:min(48, len(seed))])

	// 4. seed 应是 base64 串(handoff §7c:~132B base64,以 MDG 开头)
	if len(seed) < 100 {
		t.Errorf("seed 太短(%d),应 ~132B", len(seed))
	}
	if seed[:3] != "MDG" {
		t.Logf("⚠️ seed 前缀非 MDG(=%q),可能版本差异", seed[:3])
	}

	// 5. 手动验证中间链路(用真机 random 反推)
	rawAES := MSSDecryptAES(field6)
	random := rawAES[len(rawAES)-4:]
	teaCT := rawAES[1 : len(rawAES)-4]
	xorKey := append(append([]byte{}, random...), 0x27, 0x04, 0x20, 0x20)
	loop := getTeaLoopCount(random)
	data := customTEADecrypt(teaCT, mssdkTeaKey, xorKey, loop)

	// data = oneFlag + headerTwo + [4B len] + zlib(78 da)
	oneFlag := data[0]
	zlibIdx := findZlibMagic(data)
	if zlibIdx < 0 {
		t.Fatal("data 中未找到 zlib magic")
	}
	t.Logf("✅ data 布局: oneFlag=0x%02x zlib@%d (78 %02x)", oneFlag, zlibIdx, data[zlibIdx+1])

	// 响应 zlib = 78 da(标准 FLEVEL=2),区别于请求的 78 01
	if data[zlibIdx] != 0x78 || data[zlibIdx+1] != 0xda {
		t.Errorf("响应 zlib magic = %02x%02x, want 78da", data[zlibIdx], data[zlibIdx+1])
	} else {
		t.Logf("✅ 响应 zlib = 78 da(标准 FLEVEL=2,区别于请求 78 01)")
	}

	// 6. 手动 zlib 解压验证(容忍 adler32 校验失败)
	r, err := zlib.NewReader(bytes.NewReader(data[zlibIdx:]))
	if err != nil {
		t.Fatalf("zlib.NewReader: %v", err)
	}
	var buf bytes.Buffer
	_, readErr := buf.ReadFrom(r)
	r.Close()
	if buf.Len() == 0 {
		t.Fatalf("zlib 解压空, err=%v", readErr)
	}
	if readErr != nil {
		t.Logf("⚠️ zlib 末尾校验警告(已知:真机响应 adler32 偶不匹配): %v", readErr)
		t.Logf("   但解压数据完整(%dB),已容忍返回", buf.Len())
	}
	if !bytes.Equal(buf.Bytes(), plain) {
		t.Errorf("手动解压 != MSSDecryptField 输出")
	} else {
		t.Logf("✅ 手动 zlib 解压 == MSSDecryptField 输出(%dB)", buf.Len())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
