package crypto

// Simon 128/256 block cipher (72 rounds), used by X-Argus to encrypt the
// protobuf payload.

const (
	simonConstant uint64 = 0x3DC94C3A046D678B
	simonRounds          = 72
)

func simonRotL(v uint64, n uint) uint64 { return (v << n) | (v >> (64 - n)) }
func simonRotR(v uint64, n uint) uint64 { return (v << (64 - n)) | (v >> n) }

func simonBit(val uint64, pos int) uint64 {
	return (val >> uint(pos)) & 1
}

// simonKeyExpansion expands the 4-word (256-bit) key into 72 round keys.
func simonKeyExpansion(k [4]uint64) [simonRounds]uint64 {
	var key [simonRounds]uint64
	key[0], key[1], key[2], key[3] = k[0], k[1], k[2], k[3]
	for i := 4; i < simonRounds; i++ {
		tmp := simonRotR(key[i-1], 3)
		tmp ^= key[i-3]
		tmp ^= simonRotR(tmp, 1)
		key[i] = ^key[i-4] ^ tmp ^ simonBit(simonConstant, (i-4)%62) ^ 3
	}
	return key
}

// SimonEncryptBlock encrypts one 128-bit block (two 64-bit words) under the
// 256-bit key. Mirrors the reference with mode flag c=0.
func SimonEncryptBlock(pt [2]uint64, k [4]uint64) [2]uint64 {
	key := simonKeyExpansion(k)
	xi, xi1 := pt[0], pt[1]
	for i := 0; i < simonRounds; i++ {
		tmp := xi1
		f := simonRotL(xi1, 1) & simonRotL(xi1, 8)
		xi1 = xi ^ f ^ simonRotL(xi1, 2) ^ key[i]
		xi = tmp
	}
	return [2]uint64{xi, xi1}
}
