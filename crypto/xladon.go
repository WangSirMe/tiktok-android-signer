package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strconv"
)

// X-Ladon header generation for the native TikTok app API.
//
// Plaintext "{ts}-{lc_id}-{aid}" is encrypted by a 34-round ARX cipher whose
// round-key schedule is seeded from md5(rand4 + aid). The 4 random bytes are
// prepended to the ciphertext and the whole thing is base64-encoded.

// ladonRor is the key-schedule rotate-right, aligned to tr4cex/TikTok-Encryption
// ladon.py __ROR__: low = v<<(64-count); v = v>>count; return v | low.
// A plain 64-bit ROR — the earlier "value or low" truthiness variant was a
// mis-port of the reference's bitwise `value | low`.
func ladonRor(v uint64, count uint) uint64 {
	return (v >> count) | (v << (64 - count))
}

// ladonEncryptInput encrypts one 16-byte block using the expanded hash table.
func ladonEncryptInput(ht []byte, inp []byte) [16]byte {
	d0 := binary.LittleEndian.Uint64(inp[:8])
	d1 := binary.LittleEndian.Uint64(inp[8:16])
	for i := 0; i < 0x22; i++ {
		hv := binary.LittleEndian.Uint64(ht[i*8 : i*8+8])
		d1 = hv ^ (d0 + (d1>>8 | d1<<56))
		d0 = d1 ^ (d0>>61 | d0<<3)
	}
	var o [16]byte
	binary.LittleEndian.PutUint64(o[:8], d0)
	binary.LittleEndian.PutUint64(o[8:16], d1)
	return o
}

// ladonEncrypt runs the core routine: build the 34-entry round-key table from
// the 32-byte md5 hex seed, then ECB-encrypt the PKCS7-padded data.
func ladonEncrypt(md5hex []byte, data []byte) []byte {
	ht := make([]byte, 272+16)
	copy(ht[:32], md5hex)

	temp := make([]uint64, 0, 40)
	for i := 0; i < 4; i++ {
		temp = append(temp, binary.LittleEndian.Uint64(ht[i*8:i*8+8]))
	}
	b0, b8 := temp[0], temp[1]
	temp = temp[2:]
	for i := 0; i < 0x22; i++ {
		x9 := b0
		x8 := b8
		x8 = ladonRor(x8, 8)
		x8 = x8 + x9
		x8 = x8 ^ uint64(i)
		temp = append(temp, x8)
		x8 = x8 ^ ladonRor(x9, 61)
		binary.LittleEndian.PutUint64(ht[i*8+8:i*8+16], x8)
		b0 = x8
		b8 = temp[0]
		temp = temp[1:]
	}

	size := len(data)
	ns := ((size + 15) / 16) * 16
	ib := make([]byte, ns)
	copy(ib, data)
	for i := size; i < ns; i++ {
		ib[i] = byte(ns - size)
	}
	out := make([]byte, ns)
	for i := 0; i < ns/16; i++ {
		blk := ladonEncryptInput(ht, ib[i*16:i*16+16])
		copy(out[i*16:], blk[:])
	}
	return out
}

// xLadonWithRand generates X-Ladon using caller-supplied random bytes (testable).
func xLadonWithRand(aid, lcID, ts int64, rand4 []byte) string {
	data := strconv.FormatInt(ts, 10) + "-" + strconv.FormatInt(lcID, 10) + "-" + strconv.FormatInt(aid, 10)
	keygen := append(append([]byte{}, rand4...), []byte(strconv.FormatInt(aid, 10))...)
	md5hex := md5Hex(string(keygen))
	enc := ladonEncrypt([]byte(md5hex), []byte(data))
	out := append(append([]byte{}, rand4...), enc...)
	return base64.StdEncoding.EncodeToString(out)
}

// XLadon returns the X-Ladon header value for the given aid/lc_id/timestamp.
func XLadon(aid, lcID, ts int64) string {
	rand4 := make([]byte, 4)
	_, _ = rand.Read(rand4)
	return xLadonWithRand(aid, lcID, ts, rand4)
}
