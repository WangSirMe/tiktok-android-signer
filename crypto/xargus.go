package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"math/big"
	"strconv"
)

// X-Argus header generation for the native TikTok app API (33.2.5).
//
// Verified against real-device captures: a protobuf "bean" describing the
// device/request is Simon-encrypted, folded with an XOR pattern derived from
// mix(), wrapped with fixed markers (9B header + 2B tail), AES-CBC encrypted,
// and base64-encoded. The Simon key is derived per-request via SM3(sign_key +
// random_bytes + sign_key); the AES key material is MD5(sign_key[:16]) /
// MD5(sign_key[16:]).
//
// For POST requests, the payload hashed into field 13 and dyn_encode is
// MD5(body) as 16 raw bytes (= the X-SS-STUB value), NOT the body itself.

// argusSignKey is the protocol-wide 32-byte constant embedded in the native
// lib (base64 "wC8lD4bMTxmNVwY5jSkqi3QWmrphr/58ugLko7UZgWM="). Confirmed
// identical across real-device sub_84414 captures.
var argusSignKey, _ = hex.DecodeString(
	"c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")

// ArgusConfig holds the app-version-specific parameters.
type ArgusConfig struct {
	AID        int64
	LcID       int64
	SdkVer     string
	SdkVerCode int64
}

// DefaultArgusConfig targets TikTok Android 33.2.5 / sdk v05.00.05.
// 从 DefaultDeviceProfile 派生,换设备/版本时改 signconfig.go 即可。
var DefaultArgusConfig = ProfileAsArgusConfig(DefaultDeviceProfile)

// ArgusExtra carries the optional dyn_seed / device-token fields needed for
// strong-verification endpoints (comment/list, multi/aweme/detail).
type ArgusExtra struct {
	DynSeed     string // base64 dyn_seed from get_seed (field 24)
	DynVersion  int    // dyn algo 1-8; real device uses 5. field 26.1 = DynVersion*2 (frida 实证)
	DeviceToken string // field 16 (e.g. "Adgs7y8SLusc_AYLujTn4XUwP")
}

// argusSM3Prefix6 returns the first 6 bytes of SM3(data). Empty/nil input is
// hashed as 16 zero bytes (matches the reference body/query hash helpers).
func argusSM3Prefix6(data []byte) []byte {
	if len(data) == 0 {
		data = make([]byte, 16)
	}
	sum := SM3Sum(data)
	return sum[:6]
}

// pkcs7Pad applies PKCS#7 padding so len(out) % block == 0.
func pkcs7Pad(data []byte, block int) []byte {
	pad := block - len(data)%block
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// argusEncryptEncPb reproduces _encrypt_enc_pb: keep the first 8 bytes as an
// XOR array, XOR the rest cyclically with its first 4 bytes, then reverse the
// whole buffer.
func argusEncryptEncPb(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	for i := 8; i < len(out); i++ {
		out[i] ^= out[i%4]
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// argusMix reproduces the reference mix() — a 32-bit bit-mixing primitive
// driven by a 2-byte key. Note: the reference returns inside the loop on the
// first iteration (indentation quirk preserved faithfully).
func argusMix(key []byte) uint32 {
	var a, t uint32
	for i := 0; i < len(key); i += 2 {
		b := uint32(key[i]) ^ a
		c := (t >> 3) & 0xFFFFFFFF
		d := c ^ b
		e := d ^ t
		f := (e >> 5) & 0xFFFFFFFF
		g := (e << 11) & 0xFFFFFFFF
		h := uint32(key[i+1]) | g
		ii := f ^ h
		j := ii ^ e
		t = ^j & 0xFFFFFFFF
		return t // reference returns on first iteration
	}
	return t
}

// --- bit/byte helpers used by dyn_encode ---

func reverseBits32(n uint32) uint32 {
	var out uint32
	for i := 0; i < 32; i++ {
		out = (out << 1) | ((n >> i) & 1)
	}
	return out
}

// reverseNibbles swaps the two nibbles of each byte.
func reverseNibbles(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = (v&0xF)<<4 | (v >> 4)
	}
	return out
}

func bitSwap(b byte) byte {
	odd := b & 0x55
	even := b & 0xAA
	s := (odd << 1) | (even >> 1)
	odd2 := s & 0x33
	even2 := s & 0xCC
	return (odd2 << 2) | (even2 >> 2)
}

func byteswapNib(b byte) byte { return (b&0xF)<<4 | (b>>4)&0xF }

func byteswap32(val uint32) uint32 {
	return ((val&0xFF000000)>>24 |
		(val&0x00FF0000)>>8 |
		(val&0x0000FF00)<<8 |
		(val&0x000000FF)<<24)
}

func le4(b []byte) uint32 { return binary.LittleEndian.Uint32(b[:4]) }
func be4(b []byte) uint32 { return binary.BigEndian.Uint32(b[:4]) }

func appendBE4(v ...uint32) []byte {
	out := make([]byte, 4*len(v))
	for i, x := range v {
		binary.BigEndian.PutUint32(out[i*4:], x)
	}
	return out
}
func appendLE4(v ...uint32) []byte {
	out := make([]byte, 4*len(v))
	for i, x := range v {
		binary.LittleEndian.PutUint32(out[i*4:], x)
	}
	return out
}

// swapEnd4: big-endian uint32 → little-endian bytes (the int round-trip the
// reference uses for dyn_version 3).
func swapEnd4(b []byte) []byte {
	v := binary.BigEndian.Uint32(b[:4])
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return tmp[:]
}

func sha256First4(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:4]
}

func sha1First4(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:4]
}

func md5Digest(b []byte) [16]byte { return md5.Sum(b) }

// cipherOFBLast4LE: AES-OFB encrypt, return last 4 bytes as LE uint32.
func cipherOFBLast4LE(data []byte, hexKey string) uint32 {
	keyBytes := []byte(hexKey[:16])
	ivBytes := []byte(hexKey[16:32])
	padded := pkcs7Pad(data, 16)
	block, _ := aes.NewCipher(keyBytes)
	stream := cipher.NewOFB(block, ivBytes)
	ct := make([]byte, len(padded))
	stream.XORKeyStream(ct, padded)
	return le4(ct[len(ct)-4:])
}

// rc4 stream cipher (matches cipher.RC4 reference).
type rc4state struct {
	s    [256]byte
	i, j int
}

func newRC4(key []byte) *rc4state {
	r := &rc4state{}
	for i := range r.s {
		r.s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(r.s[i]) + int(key[i%len(key)])) % 256
		r.s[i], r.s[j] = r.s[j], r.s[i]
	}
	return r
}

func (r *rc4state) encrypt(in []byte) []byte {
	out := make([]byte, len(in))
	for k, b := range in {
		r.i = (r.i + 1) % 256
		r.j = (r.j + int(r.s[r.i])) % 256
		r.s[r.i], r.s[r.j] = r.s[r.j], r.s[r.i]
		out[k] = b ^ r.s[(int(r.s[r.i])+int(r.s[r.j]))%256]
	}
	return out
}

// --- dyn_encode (versions 1-8) ------------------------------------------------

// dynEncode computes the 12-byte field-26 value for the given version (1-8).
func dynEncode(version int, params, payload []byte, rand uint32) ([]byte, error) {
	unkSrc := []byte{0, 0, 0, 1}

	switch version {
	case 1:
		unkH := md5.Sum(unkSrc)
		ssH := md5.Sum(payload)
		pH := md5.Sum(params)
		return appendBE4(le4(unkH[:4])^rand, le4(ssH[:4])^rand, le4(pH[:4])^rand), nil
	case 2:
		unkH := md5.Sum(unkSrc)
		ssH := md5.Sum(payload)
		pH := md5.Sum(params)
		return appendBE4(
			le4(reverseNibbles(unkH[:4]))^rand,
			le4(reverseNibbles(ssH[:4]))^rand,
			le4(reverseNibbles(pH[:4]))^rand), nil
	case 3:
		unkH := md5.Sum(unkSrc)
		ssH := md5.Sum(payload)
		pH := md5.Sum(params)
		return appendBE4(
			binary.BigEndian.Uint32(swapEnd4(unkH[:4]))^0x5A5A5A5A^rand,
			binary.BigEndian.Uint32(swapEnd4(ssH[:4]))^0x5A5A5A5A^rand,
			binary.BigEndian.Uint32(swapEnd4(pH[:4]))^0x5A5A5A5A^rand), nil
	case 4:
		unkH := md5.Sum(unkSrc)
		ssH := md5.Sum(payload)
		pH := md5.Sum(params)
		return appendBE4(
			reverseBits32(be4(unkH[:4]))^rand,
			reverseBits32(be4(ssH[:4]))^rand,
			reverseBits32(be4(pH[:4]))^rand), nil
	case 5:
		unkH := SM3Sum(unkSrc)
		ssH := SM3Sum(payload)
		pH := SM3Sum(params)
		return appendBE4(le4(unkH[28:])^rand, le4(ssH[28:])^rand, le4(pH[28:])^rand), nil
	case 6:
		key := fmt.Sprintf("%032x", md5.Sum(appendBE4(rand)))
		return appendBE4(
			cipherOFBLast4LE(unkSrc, key)^rand,
			cipherOFBLast4LE(payload, key)^rand,
			cipherOFBLast4LE(params, key)^rand), nil
	case 7:
		keyHex := fmt.Sprintf("%x", md5.Sum(appendBE4(rand)))
		rc4 := newRC4([]byte(keyHex))
		encU := rc4.encrypt(unkSrc)
		for i := range encU {
			encU[i] = byteswapNib(bitSwap(encU[i]))
		}
		r := byteswap32(rand)
		md5p := md5.Sum(payload)
		ss := be4(md5p[12:]) ^ r
		p := be4(sha256First4(params)) ^ 0x5A5A5A5A ^ r
		return appendLE4(be4(encU)^r, ss, p), nil
	case 8:
		u := sha256.Sum256(unkSrc)
		unkB := make([]byte, 4)
		copy(unkB, u[:4])
		for i := range unkB {
			unkB[i] = byteswapNib(unkB[i])
		}
		var ssB [4]byte
		binary.BigEndian.PutUint32(ssB[:], crc32.ChecksumIEEE(payload))
		for i := range ssB {
			ssB[i] = byteswapNib(bitSwap(ssB[i]))
		}
		p := sha1First4(params)
		return appendBE4(le4(unkB[:])^rand, le4(ssB[:])^rand, le4(p)^0x5A5A5A5A^rand), nil
	}
	return nil, fmt.Errorf("dyn version %d not implemented", version)
}

// --- protobuf bean assembly ---------------------------------------------------

// argusBean assembles the protobuf bean aligned to the 33.2.5 real device.
//
// stubMd5 is the 16-byte MD5 of the body (= raw X-SS-STUB); for GET requests
// pass nil and field 13 will hash 16 zero bytes.
func argusBean(params []byte, stubMd5 []byte, ts int64, deviceID, versionName string,
	cfg ArgusConfig, rand3 int64, extra ArgusExtra) pbMessage {

	f13src := stubMd5
	if f13src == nil {
		f13src = make([]byte, 16) // empty body → 16 zero bytes
	}

	bean := pbMessage{
		1:  int64(0x20200929) << 1, // header magic
		2:  2,
		3:  rand3 << 1,
		4:  strconv.FormatInt(cfg.AID, 10),
		6:  strconv.FormatInt(cfg.LcID, 10),
		7:  versionName,
		8:  cfg.SdkVer,
		9:  cfg.SdkVerCode << 1,
		10: make([]byte, 8),
		12: ts << 1,
		13: argusSM3Prefix6(f13src),
		14: argusSM3Prefix6(params),
		15: pbMessage{
			1: randInt20_250() << 1,
			5: 36,
			6: 196,
			7: (ts - 1) << 1,
		},
		17: ts << 1,
		20: "none",
		21: 369 << 1,
		23: pbMessage{
			1: deviceTypeStr(),
			2: 5 << 1,
			3: DefaultDeviceProfile.Channel,
			4: int64(337675264) << 1,
		},
		25: 1 << 1,
		28: 603 << 1,
	}
	if deviceID != "" {
		bean[5] = deviceID
	}
	if extra.DeviceToken != "" {
		bean[16] = extra.DeviceToken
	}

	if extra.DynSeed != "" && extra.DynVersion != 0 {
		randU32 := uint32(rand3)
		bean[24] = extra.DynSeed
		bean[25] = 3 << 1
		// DynVersion 是 dyn algo(1-8)。field 26.1 存 algo<<1(编码约定),
		// 解出来 = algo*2(frida 实证:5→10,7→14)。dynEncode 用 algo(case 1~8)。
		dynPayload, _ := dynEncode(extra.DynVersion, params, f13src, randU32)
		bean[26] = pbMessage{
			1: int64(extra.DynVersion) << 1,
			2: dynPayload,
		}
	}
	return bean
}

func randInt20_250() int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(231)) // [0,230]
	if err != nil {
		return 100
	}
	return n.Int64() + 20
}

// deviceTypeStr returns the device model string for field 23.1 (e.g. "MI 6X").
// The protobuf encoder serializes this as a length-delimited string.
func deviceTypeStr() string {
	return "MI 6X"
}

// --- X-Argus core -------------------------------------------------------------

// calculateXArgus reproduces encode_argus_fn: Simon-encrypt the padded bean,
// fold with mix()-derived XOR key, wrap, AES-CBC, base64.
func calculateXArgus(bean pbMessage) string {
	protobuf := pkcs7Pad(pbEncode(bean), 16)
	length := len(protobuf)

	// 4 random bytes
	rb := make([]byte, 4)
	_, _ = rand.Read(rb)

	// SM3(sign_key + random_bytes + sign_key) → 32-byte Simon key
	sm3In := append(append([]byte{}, argusSignKey...), rb...)
	sm3In = append(sm3In, argusSignKey...)
	sm3Out := SM3Sum(sm3In)

	var key [4]uint64
	for i := 0; i < 4; i++ {
		key[i] = binary.LittleEndian.Uint64(sm3Out[i*8 : i*8+8])
	}

	// Simon-encrypt each 16-byte block
	encPb := make([]byte, length)
	for i := 0; i < length/16; i++ {
		pt := [2]uint64{
			binary.LittleEndian.Uint64(protobuf[i*16 : i*16+8]),
			binary.LittleEndian.Uint64(protobuf[i*16+8 : i*16+16]),
		}
		ct := SimonEncryptBlock(pt, key)
		binary.LittleEndian.PutUint64(encPb[i*16:i*16+8], ct[0])
		binary.LittleEndian.PutUint64(encPb[i*16+8:i*16+16], ct[1])
	}

	// mix(random[2:4]) → 4-byte big-endian → reversed → doubled → 8-byte XOR key
	mixed := argusMix(rb[2:4])
	var mixedBE [4]byte
	binary.BigEndian.PutUint32(mixedBE[:], mixed)
	xor4 := []byte{mixedBE[3], mixedBE[2], mixedBE[1], mixedBE[0]}
	xorKey := append([]byte{}, xor4...)
	xorKey = append(xorKey, xor4...) // 8 bytes

	prefixed := append(xorKey, encPb...)
	bBuffer := argusEncryptEncPb(prefixed)

	// 9-byte header: 0xec, rand×4, 0x01, rand, 0x02, 0x18
	header := []byte{0xec,
		randByte(), randByte(), randByte(), randByte(),
		0x01, randByte(), 0x02, 0x18}
	bBuffer = append(append(header, bBuffer...), rb[2], rb[3])

	// AES-CBC encrypt
	aesKey := md5.Sum(argusSignKey[:16])
	aesIV := md5.Sum(argusSignKey[16:])
	block, _ := aes.NewCipher(aesKey[:])
	mode := cipher.NewCBCEncrypter(block, aesIV[:])
	plain := pkcs7Pad(bBuffer, aes.BlockSize)
	ct := make([]byte, len(plain))
	mode.CryptBlocks(ct, plain)

	out := append([]byte{rb[0], rb[1]}, ct...)
	return base64.StdEncoding.EncodeToString(out)
}

func randByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	if b[0] < 0x10 {
		b[0] += 0x10
	}
	return b[0]
}

// XArgus generates the X-Argus header for a request.
//
//   - params:      raw URL query string (without leading '?')
//   - stubMd5:     16-byte MD5(body) for POST (= raw X-SS-STUB bytes); nil for GET
//   - ts:          Unix timestamp in seconds (must equal X-Khronos)
//   - deviceID:    device id used in the request
//   - versionName: app version name (e.g. "33.2.5")
//   - cfg:         app-version config
//   - extra:       optional dyn_seed / device_token for strong-verification endpoints
func XArgus(params string, stubMd5 []byte, ts int64, deviceID, versionName string,
	cfg ArgusConfig, extra ArgusExtra) string {

	n, err := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFF))
	if err != nil {
		n = big.NewInt(0)
	}
	bean := argusBean([]byte(params), stubMd5, ts, deviceID, versionName, cfg,
		n.Int64(), extra)
	return calculateXArgus(bean)
}

// ==================== X-Argus 解密(逆向 calculateXArgus)====================

// SimonDecryptBlock 是 SimonEncryptBlock 的逆:逆序跑 72 轮。
func SimonDecryptBlock(ct [2]uint64, k [4]uint64) [2]uint64 {
	key := simonKeyExpansion(k)
	xi, xi1 := ct[0], ct[1]
	for i := simonRounds - 1; i >= 0; i-- {
		// 加密轮:tmp=xi1; f=ROL(xi1,1)&ROL(xi1,8); xi1=xi^f^ROL(xi1,2)^key[i]; xi=tmp
		// 逆:   xi=tmp(=加密前的 xi1); xi1 = 加密前的 xi
		//       加密前 xi = xi1(当前) ^ f(加密前xi1) ^ ROL(加密前xi1,2) ^ key[i]
		//       加密前 xi1 = xi(当前)
		prevXi1 := xi // = 加密前的 xi1(因为加密末尾 xi=tmp=加密前xi1)
		f := simonRotL(prevXi1, 1) & simonRotL(prevXi1, 8)
		prevXi := xi1 ^ f ^ simonRotL(prevXi1, 2) ^ key[i]
		xi, xi1 = prevXi, prevXi1
	}
	return [2]uint64{xi, xi1}
}

// argusDecryptEncPb 是 argusEncryptEncPb 的逆。
// argusEncryptEncPb: ① for i:=8..: out[i]^=out[i%4]  ② reverse all
// 逆:                  ① reverse all  ② for i:=len-1..8: out[i]^=out[i%4]
func argusDecryptEncPb(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	// ① reverse (逆 of step ②)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	// ② 逆序 XOR (i 从大到小,保证 out[i%4] 还没被改)
	for i := len(out) - 1; i >= 8; i-- {
		out[i] ^= out[i%4]
	}
	return out
}

// XArgusDecrypt 解密一个 X-Argus base64 字符串,返回 protobuf bean 的原始字节。
// 用于对拍真机 X-Argus,找出我们 bean 缺失的字段。
func XArgusDecrypt(xargusB64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(xargusB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 2 {
		return nil, fmt.Errorf("too short")
	}

	// 结构:[rb[0], rb[1]] + AES-CBC 密文
	rb0, rb1 := raw[0], raw[1]
	aesCT := raw[2:]

	// AES-CBC 解密
	aesKey := md5.Sum(argusSignKey[:16])
	aesIV := md5.Sum(argusSignKey[16:])
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}
	if len(aesCT)%16 != 0 {
		return nil, fmt.Errorf("aes ct not block-aligned: %d", len(aesCT))
	}
	bBuffer := make([]byte, len(aesCT))
	cipher.NewCBCDecrypter(block, aesIV[:]).CryptBlocks(bBuffer, aesCT)
	bBuffer = pkcs7Unpad(bBuffer)

	// bBuffer 结构:[header 9B] + [argusEncryptEncPb(xorKey + encPb)] + [rb[2], rb[3]]
	if len(bBuffer) < 11 {
		return nil, fmt.Errorf("bBuffer too short: %d", len(bBuffer))
	}
	// header = [0xec, rand×4, 0x01, rand, 0x02, 0x18]
	header := bBuffer[:9]
	if header[0] != 0xec {
		return nil, fmt.Errorf("unexpected header magic: 0x%02x", header[0])
	}
	// 尾部 2 字节 = rb[2], rb[3]
	if len(bBuffer) < 11 {
		return nil, fmt.Errorf("bBuffer too short for tail")
	}
	tail := bBuffer[len(bBuffer)-2:]
	rb := []byte{rb0, rb1, tail[0], tail[1]}

	// 中间 = argusEncryptEncPb(xorKey(8) + encPb)
	middle := bBuffer[9 : len(bBuffer)-2]
	// argusDecryptEncPb
	decMiddle := argusDecryptEncPb(middle)
	// 前 8 字节 = xorKey,后面 = encPb(Simon 加密的 protobuf)
	if len(decMiddle) < 8 {
		return nil, fmt.Errorf("decMiddle too short")
	}
	encPb := decMiddle[8:]

	// Simon key = SM3(sign_key + rb + sign_key)
	sm3In := append(append([]byte{}, argusSignKey...), rb...)
	sm3In = append(sm3In, argusSignKey...)
	sm3Out := SM3Sum(sm3In)
	var key [4]uint64
	for i := 0; i < 4; i++ {
		key[i] = binary.LittleEndian.Uint64(sm3Out[i*8 : i*8+8])
	}

	// Simon 解密每个 16B block
	if len(encPb)%16 != 0 {
		return nil, fmt.Errorf("encPb not 16-aligned: %d", len(encPb))
	}
	protobuf := make([]byte, len(encPb))
	for i := 0; i < len(encPb)/16; i++ {
		ct := [2]uint64{
			binary.LittleEndian.Uint64(encPb[i*16 : i*16+8]),
			binary.LittleEndian.Uint64(encPb[i*16+8 : i*16+16]),
		}
		pt := SimonDecryptBlock(ct, key)
		binary.LittleEndian.PutUint64(protobuf[i*16:i*16+8], pt[0])
		binary.LittleEndian.PutUint64(protobuf[i*16+8:i*16+16], pt[1])
	}
	// 去 PKCS7
	protobuf = pkcs7Unpad(protobuf)
	return protobuf, nil
}
