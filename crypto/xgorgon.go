package crypto

import (
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// X-Gorgon (v8404) signature for the native TikTok app API (33.2.5).
//
// A 20-byte input is assembled from md5(params)[:4], md5(stub)[:4] (or stub
// raw bytes), md5(cookie)[:4], a fixed SDK constant, and big-endian ts. It is
// XOR'd against gorgonXorTable, then processed through nibble-swap/XOR and
// bit-reverse passes, and hex-encoded behind the "8404" tag.
//
// Aligned to the tiktok-api-main Python reference (app 33.2.5).

const gorgonLen = 20

// gorgonXorTable is the 20-byte XOR seed table extracted from the native lib.
var gorgonXorTable, _ = hex.DecodeString("ce7c47e421ff095cc9da81690147cba1ed6cc4b1")

// gorgonReverseBits reverses the bit order of a byte.
func gorgonReverseBits(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		r = (r << 1) | (b & 1)
		b >>= 1
	}
	return r
}

// XGorgon computes the X-Gorgon (v8404) header.
//
//   - params: raw URL query string without the leading '?'
//   - stub:   X-SS-STUB value (uppercase md5 hex of the body); empty for GET
//   - cookie: Cookie header value; empty if none
//   - ts:     Unix timestamp in seconds (must equal X-Khronos).
//
// The buffer is built from params[:4], MD5(body)[:4] (from stub), cookie[:4],
// a fixed SDK constant, and big-endian ts — NOT MD5(params) or MD5(cookie).
func XGorgon(params, stub, cookie string, ts int64) string {
	// Build the 20-byte input buffer (matching Python gorgon_encode):
	// [0:4]   = params[:4]  (raw bytes, NOT md5)
	// [4:8]   = MD5(body)[:4]  (stub is the uppercase hex; decode first 4 bytes)
	// [8:12]  = cookie[:4]  (raw bytes, NOT md5)
	// [12:16] = fixed SDK constant 0x20040204
	// [16:20] = big-endian ts
	buf := make([]byte, gorgonLen)

	// params[:4]
	pBytes := []byte(params)
	if len(pBytes) >= 4 {
		copy(buf[0:4], pBytes[:4])
	} else {
		copy(buf[0:4], pBytes) // pad handled by zero-init
	}

	// stub[:4] (stub is uppercase md5 hex of body; take first 4 hex bytes)
	if stub != "" {
		sLower := strings.ToLower(stub)
		if len(sLower) >= 8 {
			b, err := hex.DecodeString(sLower[:8])
			if err == nil {
				copy(buf[4:8], b[:4])
			}
		}
	}

	// cookie[:4]
	cBytes := []byte(cookie)
	if len(cBytes) >= 4 {
		copy(buf[8:12], cBytes[:4])
	} else {
		copy(buf[8:12], cBytes)
	}

	// SDK constant: bytes.fromhex("20040204")
	buf[12] = 0x20
	buf[13] = 0x04
	buf[14] = 0x02
	buf[15] = 0x04
	binary.BigEndian.PutUint32(buf[16:20], uint32(ts))

	// Pass 1: XOR each byte with gorgonXorTable.
	for i := 0; i < gorgonLen; i++ {
		buf[i] ^= gorgonXorTable[i]
	}

	// Pass 2: nibble-swap + XOR with next byte (0..18).
	for i := 0; i < gorgonLen-1; i++ {
		buf[i] = (buf[i]>>4)&0xf | (buf[i]<<4)&0xff
		buf[i] ^= buf[i+1]
	}

	// Pass 3: reverse bits + XOR 0xeb (0..18).
	for i := 0; i < gorgonLen-1; i++ {
		buf[i] = gorgonReverseBits(buf[i]) ^ 0xeb
	}

	// Final: byte 19 nibble-swap + XOR buf[0] + reverse bits + XOR 0xeb.
	buf[19] = (buf[19]>>4)&0xf | (buf[19]<<4)&0xff
	buf[19] ^= buf[0]
	buf[19] = gorgonReverseBits(buf[19]) ^ 0xeb

	// Tag: "8404" (arm64) + random header2 (1st byte divisible by 4) + "0000".
	var sb strings.Builder
	sb.WriteString("8404")
	h2b0 := []byte{0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0}
	var rb [1]byte
	_, _ = crand.Read(rb[:])
	sb.WriteString(fmt.Sprintf("%02x", h2b0[int(rb[0])%len(h2b0)]))
	_, _ = crand.Read(rb[:])
	sb.WriteString(fmt.Sprintf("%02x", rb[0]))
	sb.WriteString("0000")
	for _, v := range buf {
		sb.WriteString(fmt.Sprintf("%02x", v))
	}
	return sb.String()
}

// XKhronos returns the X-Khronos header value (Unix timestamp as a decimal string).
func XKhronos(ts int64) string {
	return strconv.FormatInt(ts, 10)
}

// swapNibbles exchanges the high and low nibbles of b.
func swapNibbles(b byte) byte {
	return (b << 4) | (b >> 4)
}

// reverseBits reverses the bit order of b (alias for gorgonReverseBits).
func reverseBits(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		r = (r << 1) | (b & 1)
		b >>= 1
	}
	return r
}

// md5Hex is defined in xgnarly.go (shared across the package).
