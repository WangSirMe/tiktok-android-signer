package crypto

import "encoding/binary"

// SM3 hash (GB/T 32905-2016), used by X-Argus for the body/query hashes.

var sm3IV = [8]uint32{
	0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
	0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
}

func sm3RotL(x uint32, k uint) uint32 {
	k &= 31
	return (x << k) | (x >> (32 - k))
}

func sm3T(j int) uint32 {
	if j < 16 {
		return 0x79cc4519
	}
	return 0x7a879d8a
}

func sm3FF(x, y, z uint32, j int) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (x & z) | (y & z)
}

func sm3GG(x, y, z uint32, j int) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (^x & z)
}

func sm3P0(x uint32) uint32 { return x ^ sm3RotL(x, 9) ^ sm3RotL(x, 17) }
func sm3P1(x uint32) uint32 { return x ^ sm3RotL(x, 15) ^ sm3RotL(x, 23) }

func sm3CF(v *[8]uint32, block []byte) {
	var w [68]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[i*4 : i*4+4])
	}
	for j := 16; j < 68; j++ {
		w[j] = sm3P1(w[j-16]^w[j-9]^sm3RotL(w[j-3], 15)) ^ sm3RotL(w[j-13], 7) ^ w[j-6]
	}
	var w1 [64]uint32
	for j := 0; j < 64; j++ {
		w1[j] = w[j] ^ w[j+4]
	}

	a, b, c, d := v[0], v[1], v[2], v[3]
	e, f, g, h := v[4], v[5], v[6], v[7]
	for j := 0; j < 64; j++ {
		ss1 := sm3RotL(sm3RotL(a, 12)+e+sm3RotL(sm3T(j), uint(j)), 7)
		ss2 := ss1 ^ sm3RotL(a, 12)
		tt1 := sm3FF(a, b, c, j) + d + ss2 + w1[j]
		tt2 := sm3GG(e, f, g, j) + h + ss1 + w[j]
		d = c
		c = sm3RotL(b, 9)
		b = a
		a = tt1
		h = g
		g = sm3RotL(f, 19)
		f = e
		e = sm3P0(tt2)
	}
	v[0] ^= a
	v[1] ^= b
	v[2] ^= c
	v[3] ^= d
	v[4] ^= e
	v[5] ^= f
	v[6] ^= g
	v[7] ^= h
}

// SM3Sum returns the 32-byte SM3 digest of msg.
func SM3Sum(msg []byte) [32]byte {
	l := len(msg)
	buf := make([]byte, l, l+72)
	copy(buf, msg)
	buf = append(buf, 0x80)
	for len(buf)%64 != 56 {
		buf = append(buf, 0x00)
	}
	var lenBytes [8]byte
	binary.BigEndian.PutUint64(lenBytes[:], uint64(l)*8)
	buf = append(buf, lenBytes[:]...)

	v := sm3IV
	for i := 0; i < len(buf); i += 64 {
		sm3CF(&v, buf[i:i+64])
	}

	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:i*4+4], v[i])
	}
	return out
}
