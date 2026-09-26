package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestMSSDKCompressE2E 端到端验证:用 mssdkCompress(魔改 deflate)压缩真机明文,
// 输出应逐字节匹配真机抓取的 [4B len prefix] + [78 01 zlib stream]。
//
// 真机数据(hook_compress2.js 从 libmetasec_ov.so sub_11D508 抓取):
//
//	输入(75B) → compress2(level=-1→6) → 80B zlib 流
//	mssdkCompress 再前置 4B 长度 → 84B
func TestMSSDKCompressE2E(t *testing.T) {
	inHex := "0a206334616565393930313761383462666438636634646230323063383566306161" +
		"121337363539333533323030303236353032363537" +
		"1a07616e64726f6964" +
		"22097630352e30302e3035"
	realZlibHex := "780115c33b0a80300c06e05174d4cd493c40f96d9b3e8e93260db82838787e71f8a64" +
		"d22f75e2b8ecc2536d32216b5c1430a1998e72527aa818207e013fdf23af0a5cf7de" +
		"a3ebe200738d007e19f12cc"

	plain, _ := hex.DecodeString(inHex)
	realZlib, _ := hex.DecodeString(realZlibHex)

	want := make([]byte, 4+len(realZlib))
	binary.LittleEndian.PutUint32(want[:4], uint32(len(plain)))
	copy(want[4:], realZlib)

	got, err := mssdkCompress(plain)
	if err != nil {
		t.Fatalf("mssdkCompress: %v", err)
	}

	t.Logf("got  (%d): %x", len(got), got)
	t.Logf("want (%d): %x", len(want), want)

	if bytes.Equal(got, want) {
		t.Logf("✅✅✅ mssdkCompress 端到端逐字节匹配真机!")
	} else {
		t.Errorf("❌ 不匹配")
		n := len(got)
		if len(want) > n {
			n = len(want)
		}
		for i := 0; i < n; i++ {
			var g, w byte
			if i < len(got) {
				g = got[i]
			}
			if i < len(want) {
				w = want[i]
			}
			if g != w {
				t.Logf("  [%d] got=%02x want=%02x <<<", i, g, w)
			}
		}
	}
}
