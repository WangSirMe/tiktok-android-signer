package crypto

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	customB64Alphabet   = "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe="
	standardB64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	magicConstant       = 536919696
)

var (
	filterIndices = []int{3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 4, 6, 8, 10, 12, 14, 16, 18, 20}
	scrambleOrder = []int{0, 10, 1, 11, 2, 12, 3, 13, 4, 14, 5, 15, 6, 16, 7, 17, 8, 18, 9}
)

func md5Twice(data string) string {
	first := md5.Sum([]byte(data))
	second := md5.Sum(first[:])
	return hex.EncodeToString(second[:])
}

func rc4Encrypt(plaintext []byte, key []int) []byte {
	sBox := make([]int, 256)
	for i := range sBox {
		sBox[i] = i
	}
	index := 0
	for i := 0; i < 256; i++ {
		index = (index + sBox[i] + key[i%len(key)]) % 256
		sBox[i], sBox[index] = sBox[index], sBox[i]
	}
	i, index := 0, 0
	ciphertext := make([]byte, len(plaintext))
	for j, b := range plaintext {
		i = (i + 1) % 256
		index = (index + sBox[i]) % 256
		sBox[i], sBox[index] = sBox[index], sBox[i]
		keystream := sBox[(sBox[i]+sBox[index])%256]
		ciphertext[j] = b ^ byte(keystream)
	}
	return ciphertext
}

func b64Encode(data []byte, keyTable string) string {
	if keyTable == "" {
		keyTable = standardB64Alphabet
	}
	var lastList []int
	for i := 0; i < len(data); i += 3 {
		num1 := int(data[i])
		var arr1, arr2, arr3, arr4 int
		if i+2 < len(data) {
			num2 := int(data[i+1])
			num3 := int(data[i+2])
			arr1 = num1 >> 2
			arr2 = ((3 & num1) << 4) | (num2 >> 4)
			arr3 = ((15 & num2) << 2) | (num3 >> 6)
			arr4 = 63 & num3
		} else if i+1 < len(data) {
			num2 := int(data[i+1])
			arr1 = num1 >> 2
			arr2 = ((3 & num1) << 4) | (num2 >> 4)
			arr3 = 64
			arr4 = 64
		} else {
			arr1 = num1 >> 2
			arr2 = ((3 & num1) << 4) | 0
			arr3 = 64
			arr4 = 64
		}
		lastList = append(lastList, arr1, arr2, arr3, arr4)
	}
	out := make([]byte, len(lastList))
	for i, v := range lastList {
		out[i] = keyTable[v]
	}
	return string(out)
}

func filterNums(numList []int) []int {
	out := make([]int, len(filterIndices))
	for i, idx := range filterIndices {
		out[i] = numList[idx-1]
	}
	return out
}

func scramble(values []int) []byte {
	b := make([]byte, len(scrambleOrder))
	for i, idx := range scrambleOrder {
		b[i] = byte(values[idx])
	}
	return b
}

func checksum(saltList []int) int {
	cs := 64
	for _, v := range saltList[3:] {
		cs ^= v
	}
	return cs
}

// GenerateXBogus 根据 query 字符串和 UA 生成 X-Bogus（Web V2）。
func GenerateXBogus(queryString, userAgent, body string, timestamp int64) string {
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}

	md5Params := md5Twice(queryString)
	md5Body := md5Twice(body)
	uaB64 := b64Encode(rc4Encrypt([]byte(userAgent), []int{0, 1, 14}), standardB64Alphabet)
	md5UA := fmt.Sprintf("%x", md5.Sum([]byte(uaB64)))

	paramsBytes, _ := hex.DecodeString(md5Params)
	bodyBytes, _ := hex.DecodeString(md5Body)
	uaBytes, _ := hex.DecodeString(md5UA)

	saltList := []int{
		int(timestamp),
		magicConstant,
		64,
		0,
		1,
		14,
		int(paramsBytes[len(paramsBytes)-2]),
		int(paramsBytes[len(paramsBytes)-1]),
		int(bodyBytes[len(bodyBytes)-2]),
		int(bodyBytes[len(bodyBytes)-1]),
		int(uaBytes[len(uaBytes)-2]),
		int(uaBytes[len(uaBytes)-1]),
	}
	for shift := 24; shift >= 0; shift -= 8 {
		saltList = append(saltList, int((timestamp>>shift)&0xFF))
	}
	for shift := 24; shift >= 0; shift -= 8 {
		saltList = append(saltList, int((int64(saltList[1])>>shift)&0xFF))
	}
	saltList = append(saltList, checksum(saltList), 255)

	filtered := filterNums(saltList)
	encrypted := rc4Encrypt(scramble(filtered), []int{255})
	payload := append([]byte{0x02, 0xff}, encrypted...)
	return b64Encode(payload, customB64Alphabet)
}
