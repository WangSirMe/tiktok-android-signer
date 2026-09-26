package mflate

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestMSSDKDeflateMatch 用真机抓取的明文,验证 mflate(forked)输出逐字节 == 真机 zlib 流。
//
// 真机数据(hook_compress2.js 从 libmetasec_ov.so sub_11D508 抓取):
//
//	输入(75B protobuf) → 真机输出(80B zlib,level=-1→6,dynamic Huffman)
//
// 魔改点:
//  1. zlib header = 78 01(FLEVEL 硬编码为 0,不随 level 变化)
//  2. 块类型选择:符号数 >= 0x30(48) → dynamic,否则 fixed(标准库是比 dynamicSize < fixedSize)
func TestMSSDKDeflateMatch(t *testing.T) {
	inHex := "0a206334616565393930313761383462666438636634646230323063383566306161" +
		"121337363539333533323030303236353032363537" +
		"1a07616e64726f6964" +
		"22097630352e30302e3035"
	wantHex := "780115c33b0a80300c06e05174d4cd493c40f96d9b3e8e93260db82838787e71f8a64" +
		"d22f75e2b8ecc2536d32216b5c1430a1998e72527aa818207e013fdf23af0a5cf7de" +
		"a3ebe200738d007e19f12cc"

	plain, _ := hex.DecodeString(inHex)
	want, _ := hex.DecodeString(wantHex)

	// 用 mflate level 6 (= Z_DEFAULT_COMPRESSION 真机实际 level) 压缩。
	var buf bytes.Buffer
	zw, err := NewWriter(&buf, 6)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := zw.Write(plain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 注意:mflate(原 flate)只产出 raw deflate 流,不带 zlib header。
	// 真机输出 = [78 01 zlib header] + [deflate 流] + [adler32 4B]。
	// 我们在测试里手动加 header + adler32 验证 deflate 体。
	gotDeflate := buf.Bytes()

	t.Logf("plain      (%d): %x", len(plain), plain)
	t.Logf("got deflate (%d): %x", len(gotDeflate), gotDeflate)

	// 真机 deflate 体 = want[2:-4](去 zlib header + adler32)
	wantDeflate := want[2 : len(want)-4]
	t.Logf("want deflate(%d): %x", len(wantDeflate), wantDeflate)

	if bytes.Equal(gotDeflate, wantDeflate) {
		t.Logf("✅ deflate body 逐字节匹配真机!")
	} else {
		t.Errorf("❌ deflate body 不匹配:\n got  = %x\n want = %x", gotDeflate, wantDeflate)

		// 逐字节 diff
		n := len(gotDeflate)
		if len(wantDeflate) > n {
			n = len(wantDeflate)
		}
		for i := 0; i < n; i++ {
			var g, w byte
			if i < len(gotDeflate) {
				g = gotDeflate[i]
			}
			if i < len(wantDeflate) {
				w = wantDeflate[i]
			}
			if g != w {
				t.Logf("  [%d] got=%02x want=%02x %s", i, g, w, diffMark(g, w))
			}
		}
	}

	// 块类型检查
	if len(gotDeflate) > 0 {
		bfinal := gotDeflate[0] & 1
		btype := (gotDeflate[0] >> 1) & 3
		types := map[int]string{0: "stored", 1: "fixed", 2: "dynamic", 3: "error"}
		t.Logf("got block: BFINAL=%d BTYPE=%d(%s)", bfinal, btype, types[int(btype)])
	}
	if len(wantDeflate) > 0 {
		bfinal := wantDeflate[0] & 1
		btype := (wantDeflate[0] >> 1) & 3
		types := map[int]string{0: "stored", 1: "fixed", 2: "dynamic", 3: "error"}
		t.Logf("want block: BFINAL=%d BTYPE=%d(%s)", bfinal, btype, types[int(btype)])
	}
}

func diffMark(a, b byte) string {
	if a != b {
		return "<<< DIFF"
	}
	return ""
}
