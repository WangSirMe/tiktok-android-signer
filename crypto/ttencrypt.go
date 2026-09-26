package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
)

// TTEncrypt (TTEncrypt05) body encryption for the device_register endpoint.
//
// The native routine is a hand-rolled SHA-512 + AES-128-CBC; reduced here to Go
// stdlib. Layout:
//
//	magic(6) || salt(32) || AES128-CBC( SHA512(pt) || pt, PKCS7 )
//
// where key||iv = SHA512( SHA512(salt) || ttEncryptOrdList )[:32]. The plaintext
// pt is the gzipped payload with its 10-byte gzip header normalized to zeros.
//
// Only encryption is needed (the server decrypts); the public reference's broken
// decrypt path is intentionally omitted.

var ttEncryptMagic = []byte{0x74, 0x63, 0x05, 0x10, 0x00, 0x00}

// ttEncryptOrdList is the 64-byte constant mixed into the key derivation,
// extracted from the native lib's rodata.
var ttEncryptOrdList, _ = hex.DecodeString(
	"4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524" +
		"f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58")

// ttEncryptWithSalt encrypts pt using a caller-supplied salt (testable).
// pt must already be gzip-framed (first 10 bytes are normalized to the gzip
// header by the caller or are the gzip header).
func ttEncryptWithSalt(pt, salt []byte) []byte {
	h1 := sha512.Sum512(salt)
	keyiv := sha512.Sum512(append(h1[:], ttEncryptOrdList...))
	key, iv := keyiv[:16], keyiv[16:32]

	inner := append(sha512Sum(pt), pt...)
	inner = pkcs7Pad(inner, 16)

	block, _ := aes.NewCipher(key)
	ct := make([]byte, len(inner))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, inner)

	out := make([]byte, 0, len(ttEncryptMagic)+len(salt)+len(ct))
	out = append(out, ttEncryptMagic...)
	out = append(out, salt...)
	out = append(out, ct...)
	return out
}

// TTEncrypt encrypts a gzip-framed payload into a TTEncrypt05 device_register body.
func TTEncrypt(gzipPayload []byte) []byte {
	salt := make([]byte, 32)
	_, _ = rand.Read(salt)
	return ttEncryptWithSalt(gzipPayload, salt)
}

func sha512Sum(b []byte) []byte {
	s := sha512.Sum512(b)
	return s[:]
}
