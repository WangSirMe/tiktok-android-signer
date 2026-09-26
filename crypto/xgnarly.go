package crypto

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"time"
)

const (
	gnarlyAlphabet    = "u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP="
	magicByte         = 75
	defaultCanvas     = 3181061566
	defaultSDKVersion = "1.0.0.368"
	defaultVersionTag = "5.1.3-ZTCA"
)

var (
	sigma      = []uint32{1196819126, 600974999, 3863347763, 1451689750}
	fieldOrder = []int{1, 8, 12, 11, 6, 9, 4, 7, 0, 14, 15, 2, 3, 10, 5, 13}
	intWidths  = map[int]int{
		0: 4, 1: 2, 2: 2, 6: 4, 7: 4, 8: 4, 11: 2, 12: 2, 13: 2, 14: 4, 15: 4,
	}
	defaultCounters = map[string]int{
		"totalXHRRequests": 63, "totalFetchRequests": 43,
		"interceptedXHRRequests": 10, "interceptedFetchRequests": 6,
	}
)

func u32(v uint32) uint32 { return v & 0xFFFFFFFF }

func rotl(v uint32, shift int) uint32 {
	return u32((v << shift) | (v >> (32 - shift)))
}

func quarter(state []uint32, a, b, c, d int) {
	state[a] = u32(state[a] + state[b])
	state[d] = rotl(state[d]^state[a], 16)
	state[c] = u32(state[c] + state[d])
	state[b] = rotl(state[b]^state[c], 12)
	state[a] = u32(state[a] + state[b])
	state[d] = rotl(state[d]^state[a], 8)
	state[c] = u32(state[c] + state[d])
	state[b] = rotl(state[b]^state[c], 7)
}

func chachaBlock(initial []uint32, rounds int) []uint32 {
	state := append([]uint32(nil), initial...)
	roundCount := 0
	for roundCount < rounds {
		quarter(state, 0, 4, 8, 12)
		quarter(state, 1, 5, 9, 13)
		quarter(state, 2, 6, 10, 14)
		quarter(state, 3, 7, 11, 15)
		roundCount++
		if roundCount >= rounds {
			break
		}
		quarter(state, 0, 5, 10, 15)
		quarter(state, 1, 6, 11, 12)
		quarter(state, 2, 7, 12, 13)
		quarter(state, 3, 4, 13, 14)
		roundCount++
	}
	for i := range state {
		state[i] = u32(state[i] + initial[i])
	}
	return state
}

func chachaXOR(data []byte, keyWords []uint32, rounds int) {
	state := append(append([]uint32(nil), sigma...), keyWords...)
	offset := 0
	for offset < len(data) {
		stream := chachaBlock(state, rounds)
		state[12] = u32(state[12] + 1)
		limit := 64
		if len(data)-offset < limit {
			limit = len(data) - offset
		}
		for i := 0; i < limit; i++ {
			word := stream[i>>2]
			b := byte((word >> (8 * (i & 3))) & 0xFF)
			data[offset+i] ^= b
		}
		offset += limit
	}
}

func deriveRounds(keyWords []uint32) int {
	rounds := 0
	for _, word := range keyWords {
		rounds = (rounds + int(word&15)) & 15
	}
	return rounds + 5
}

func encodeGnarlyBase64(data []byte) string {
	var out []byte
	index := 0
	for index+3 <= len(data) {
		block := (int(data[index]) << 16) | (int(data[index+1]) << 8) | int(data[index+2])
		out = append(out,
			gnarlyAlphabet[(block>>18)&63],
			gnarlyAlphabet[(block>>12)&63],
			gnarlyAlphabet[(block>>6)&63],
			gnarlyAlphabet[block&63],
		)
		index += 3
	}
	remaining := len(data) - index
	if remaining == 1 {
		block := int(data[index]) << 16
		out = append(out,
			gnarlyAlphabet[(block>>18)&63],
			gnarlyAlphabet[(block>>12)&63],
			'=', '=')
	} else if remaining == 2 {
		block := (int(data[index]) << 16) | (int(data[index+1]) << 8)
		out = append(out,
			gnarlyAlphabet[(block>>18)&63],
			gnarlyAlphabet[(block>>12)&63],
			gnarlyAlphabet[(block>>6)&63],
			'=')
	}
	return string(out)
}

func intToFixedBytes(value int, width int) []byte {
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		out[i] = byte(value & 0xFF)
		value /= 256
	}
	return out
}

type fieldValue struct {
	intVal *int
	strVal *string
}

func encodePayload(fields map[int]fieldValue) []byte {
	xorHeader := uint32(0)
	for _, v := range fields {
		if v.intVal != nil {
			xorHeader = u32(xorHeader ^ uint32(*v.intVal))
		}
	}
	fields[0] = fieldValue{intVal: intPtr(int(xorHeader))}

	var present []int
	for _, key := range fieldOrder {
		if _, ok := fields[key]; ok {
			present = append(present, key)
		}
	}

	out := []byte{byte(len(present))}
	for _, key := range present {
		v := fields[key]
		var valueBytes []byte
		if v.intVal != nil {
			width := intWidths[key]
			valueBytes = intToFixedBytes(*v.intVal, width)
		} else {
			valueBytes = []byte(*v.strVal)
		}
		out = append(out, byte(key&0xFF))
		length := len(valueBytes)
		out = append(out, byte(length>>8), byte(length&0xFF))
		out = append(out, valueBytes...)
	}
	return out
}

func intPtr(v int) *int       { return &v }
func strPtr(v string) *string { return &v }

func md5Hex(text string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(text)))
}

// GenerateXGnarly 生成 X-Gnarly 签名。
func GenerateXGnarly(queryString, userAgent, body string) string {
	if body == "" {
		body = ""
	}
	ts := time.Now().UnixMilli()

	randomLow16 := make([]byte, 2)
	random32 := make([]byte, 4)
	randomKey := make([]byte, 48)
	_, _ = rand.Read(randomLow16)
	_, _ = rand.Read(random32)
	_, _ = rand.Read(randomKey)

	field14 := (65 << 16) | (int(randomLow16[0]) << 8) | int(randomLow16[1])
	field15 := u32((uint32(random32[0]) << 24) | (uint32(random32[1]) << 16) | (uint32(random32[2]) << 8) | uint32(random32[3]))

	counters := map[string]int{}
	for k, v := range defaultCounters {
		counters[k] = v
	}

	fields := map[int]fieldValue{
		1:  {intVal: intPtr(65)},
		2:  {intVal: intPtr(4)},
		3:  {strVal: strPtr(md5Hex(queryString))},
		4:  {strVal: strPtr(md5Hex(body))},
		5:  {strVal: strPtr(md5Hex(userAgent))},
		6:  {intVal: intPtr(int(ts / 1000))},
		7:  {intVal: intPtr(defaultCanvas)},
		8:  {intVal: intPtr(int(ts % 0x80000000))},
		9:  {strVal: strPtr(defaultVersionTag)},
		10: {strVal: strPtr(defaultSDKVersion)},
		11: {intVal: intPtr(1)},
		12: {intVal: intPtr(counters["totalXHRRequests"] + counters["totalFetchRequests"])},
		13: {intVal: intPtr(counters["interceptedXHRRequests"] + counters["interceptedFetchRequests"])},
		14: {intVal: intPtr(field14)},
		15: {intVal: intPtr(int(field15))},
	}

	plaintext := encodePayload(fields)
	keyWords := make([]uint32, 12)
	for i := 0; i < 12; i++ {
		keyWords[i] = u32(uint32(randomKey[i*4]) | (uint32(randomKey[i*4+1]) << 8) | (uint32(randomKey[i*4+2]) << 16) | (uint32(randomKey[i*4+3]) << 24))
	}
	rounds := deriveRounds(keyWords)

	cipher := append([]byte(nil), plaintext...)
	chachaXOR(cipher, keyWords, rounds)

	mod := len(cipher) + 1
	insertPos := 0
	for _, b := range randomKey {
		insertPos = (insertPos + int(b)) % mod
	}
	for _, b := range cipher {
		insertPos = (insertPos + int(b)) % mod
	}

	output := make([]byte, 1+len(cipher)+48)
	output[0] = magicByte
	copy(output[1:1+insertPos], cipher[:insertPos])
	copy(output[1+insertPos:1+insertPos+48], randomKey)
	copy(output[1+insertPos+48:], cipher[insertPos:])

	return encodeGnarlyBase64(output)
}
