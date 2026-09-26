// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mflate

import (
	"math"
	"math/bits"
	"sort"
)

// hcode is a huffman code with a bit code and bit length.
type hcode struct {
	code, len uint16
}

type huffmanEncoder struct {
	codes     []hcode
	freqcache []literalNode
	bitCount  [17]int32
	lns       byLiteral // stored to avoid repeated allocation in generate
	lfs       byFreq    // stored to avoid repeated allocation in generate
}

type literalNode struct {
	literal uint16
	freq    int32
}

// A levelInfo describes the state of the constructed tree for a given depth.
type levelInfo struct {
	// Our level.  for better printing
	level int32

	// The frequency of the last node at this level
	lastFreq int32

	// The frequency of the next character to add to this level
	nextCharFreq int32

	// The frequency of the next pair (from level below) to add to this level.
	// Only valid if the "needed" value of the next lower level is 0.
	nextPairFreq int32

	// The number of chains remaining to generate for this level before moving
	// up to the next level
	needed int32
}

// set sets the code and length of an hcode.
func (h *hcode) set(code uint16, length uint16) {
	h.len = length
	h.code = code
}

func maxNode() literalNode { return literalNode{math.MaxUint16, math.MaxInt32} }

func newHuffmanEncoder(size int) *huffmanEncoder {
	return &huffmanEncoder{codes: make([]hcode, size)}
}

// Generates a HuffmanCode corresponding to the fixed literal table.
func generateFixedLiteralEncoding() *huffmanEncoder {
	h := newHuffmanEncoder(maxNumLit)
	codes := h.codes
	var ch uint16
	for ch = 0; ch < maxNumLit; ch++ {
		var bits uint16
		var size uint16
		switch {
		case ch < 144:
			// size 8, 000110000  .. 10111111
			bits = ch + 48
			size = 8
		case ch < 256:
			// size 9, 110010000 .. 111111111
			bits = ch + 400 - 144
			size = 9
		case ch < 280:
			// size 7, 0000000 .. 0010111
			bits = ch - 256
			size = 7
		default:
			// size 8, 11000000 .. 11000111
			bits = ch + 192 - 280
			size = 8
		}
		codes[ch] = hcode{code: reverseBits(bits, byte(size)), len: size}
	}
	return h
}

func generateFixedOffsetEncoding() *huffmanEncoder {
	h := newHuffmanEncoder(30)
	codes := h.codes
	for ch := range codes {
		codes[ch] = hcode{code: reverseBits(uint16(ch), 5), len: 5}
	}
	return h
}

var fixedLiteralEncoding *huffmanEncoder = generateFixedLiteralEncoding()
var fixedOffsetEncoding *huffmanEncoder = generateFixedOffsetEncoding()

func (h *huffmanEncoder) bitLength(freq []int32) int {
	var total int
	for i, f := range freq {
		if f != 0 {
			total += int(f) * int(h.codes[i].len)
		}
	}
	return total
}

const maxBitsLimit = 16

// ============================================================================
// MSSDK zlib 兼容 Huffman 树构造
// ============================================================================
//
// Go flate 原始的 bitCounts 用 level-based 算法,和标准 C zlib 的 heap-based
// build_tree + gen_bitlen 对同一频率分布产生不同码长(差 1 bit),导致 deflate
// 流不匹配。这里用标准 zlib 1.x 的算法替换,确保与 MSSDK(标准 zlib 魔改)一致。
//
// 参考:zlib trees.c build_tree / gen_bitlen / gen_codes / pqdownheap。

// heapSize 是 zlib 的 HEAP_SIZE = 2*L_CODES+1。L_CODES=286 → HEAP_SIZE=573。
// 对 literal/length tree 用 573;对 distance/code-length tree 用更小值。
// 取足够大的值。
const heapSize = 2*maxNumLit + 1

// zlibHeap 实现 zlib 的最小堆(Build tree 用)。
type zlibHeap struct {
	heap    [heapSize]int // heap[1..heapLen] 有效,0 不用;heapMax..HEAP_SIZE-1 存排序后的节点
	heapLen int
	heapMax int
	depth   [heapSize]uint8 // 子树深度
}

func newZlibHeap() zlibHeap {
	var h zlibHeap
	// 哨兵:-1 表示未使用(避免和合法符号 0 混淆)
	for i := range h.heap {
		h.heap[i] = -1
	}
	return h
}

// smaller 对齐 zlib 的 smaller 宏:
//
// zlibSmaller 对齐 MSSDK 魔改 smaller:
//
//	标准 zlib: freq[n] < freq[m] || (freq 相等 && depth[n] <= depth[m])
//	MSSDK 魔改: freq[n] < freq[m] || (freq 相等 && n < m)
//
// 差异:同频率时 MSSDK 比较符号号(小的优先),标准 zlib 比较 depth。
// 这导致同频率符号的 Huffman 码长分配不同(实测 4 个符号差 1 bit)。
func zlibSmaller(treeFreq []int32, depth []uint8, n, m int) bool {
	if treeFreq[n] != treeFreq[m] {
		return treeFreq[n] < treeFreq[m]
	}
	// MSSDK 魔改:用符号号代替 depth 做 tie-breaking。
	return n < m
}

// pqdownheap 对齐 zlib pqdownheap:从 heap[k] 开始向下堆化。
// treeFreq 是所有节点(叶子+内部)的频率表。
func pqdownheap(treeFreq []int32, depth []uint8, h *zlibHeap, k int) {
	v := h.heap[k]
	j := k << 1
	for j <= h.heapLen {
		if j < h.heapLen && zlibSmaller(treeFreq, depth, h.heap[j+1], h.heap[j]) {
			j++
		}
		if zlibSmaller(treeFreq, depth, v, h.heap[j]) {
			break
		}
		h.heap[k] = h.heap[j]
		k = j
		j <<= 1
	}
	h.heap[k] = v
}

// zlibBuildTree 对齐 zlib build_tree + gen_bitlen + gen_codes。
// 从 freq 构造 Huffman 码长 + 码字,写入 h.codes。
// maxBits 是最大码长(literal=15, distance=15, code-length=7)。
func (h *huffmanEncoder) zlibBuildTree(freq []int32, maxBits int32) {
	elems := len(freq)
	// 扁平数组:treeFreq[node]=频率, treeDad[node]=父节点, treeLen[node]=码长
	// 节点编号 0..elems-1 是叶子, elems.. 是内部节点。
	totalNodes := 2*elems + 1
	treeFreq := make([]int32, totalNodes)
	treeDad := make([]int, totalNodes)
	treeLen := make([]uint16, totalNodes)

	var zh = newZlibHeap()
	zh.heapLen = 0
	zh.heapMax = heapSize

	maxCode := -1
	for n := 0; n < elems; n++ {
		if freq[n] != 0 {
			zh.heapLen++
			zh.heap[zh.heapLen] = n
			maxCode = n
			zh.depth[n] = 0
			treeFreq[n] = freq[n]
		} else {
			treeLen[n] = 0
		}
	}

	// pkzip 要求至少 2 个非零码
	for zh.heapLen < 2 {
		zh.heapLen++
		if maxCode < 2 {
			maxCode++
			zh.heap[zh.heapLen] = maxCode
		} else {
			zh.heap[zh.heapLen] = 0
		}
		nd := zh.heap[zh.heapLen]
		treeFreq[nd] = 1
		zh.depth[nd] = 0
	}

	// 建初始堆
	for n := zh.heapLen / 2; n >= 1; n-- {
		pqdownheap(treeFreq, zh.depth[:], &zh, n)
	}

	// 反复合并最小两个节点
	nextNode := elems // 下一个内部节点编号
	for {
		// pqremove: 取堆顶(最小)
		n := zh.heap[1]
		zh.heap[1] = zh.heap[zh.heapLen]
		zh.heapLen--
		pqdownheap(treeFreq, zh.depth[:], &zh, 1)

		m := zh.heap[1] // 第二小
		zh.heapMax--
		zh.heap[zh.heapMax] = n
		zh.heapMax--
		zh.heap[zh.heapMax] = m

		// 新内部节点
		treeFreq[nextNode] = treeFreq[n] + treeFreq[m]
		if zh.depth[n] >= zh.depth[m] {
			zh.depth[nextNode] = zh.depth[n] + 1
		} else {
			zh.depth[nextNode] = zh.depth[m] + 1
		}
		treeDad[n] = nextNode
		treeDad[m] = nextNode

		zh.heap[1] = nextNode
		nextNode++
		pqdownheap(treeFreq, zh.depth[:], &zh, 1)

		if zh.heapLen < 2 {
			break
		}
	}
	zh.heapMax--
	zh.heap[zh.heapMax] = zh.heap[1]

	// gen_bitlen: 按树深度分配码长
	var blCount [17]int32
	maxLength := int(maxBits)
	overflow := 0

	// 根节点码长=0
	treeLen[zh.heap[zh.heapMax]] = 0

	for hIdx := zh.heapMax + 1; hIdx < heapSize; hIdx++ {
		n := zh.heap[hIdx]
		if n < 0 {
			continue // 哨兵,未使用
		}
		bits := int(treeLen[treeDad[n]]) + 1
		if bits > maxLength {
			bits = maxLength
			overflow++
		}
		treeLen[n] = uint16(bits)
		if n > maxCode {
			continue // 内部节点
		}
		blCount[bits]++
	}

	// 处理溢出(码长超过 maxBits)
	if overflow > 0 {
		for overflow > 0 {
			bits := maxLength - 1
			for blCount[bits] == 0 {
				bits--
			}
			blCount[bits]--
			blCount[bits+1] += 2
			blCount[maxLength]--
			overflow -= 2
		}
		// 重新扫描:从高到低按 blCount 分配码长
		h2 := heapSize - 1
		for bits := maxLength; bits != 0; bits-- {
			n2 := blCount[bits]
			for n2 != 0 {
				h2--
				m2 := zh.heap[h2]
				if m2 < 0 || m2 > maxCode {
					continue
				}
				if int(treeLen[m2]) != bits {
					treeLen[m2] = uint16(bits)
				}
				n2--
			}
		}
	}

	// gen_codes:从 blCount 生成规范 Huffman 码
	var nextCode [17]uint16
	var code uint16
	for bits := int32(1); bits <= maxBits; bits++ {
		code = (code + uint16(blCount[bits-1])) << 1
		nextCode[bits] = code
	}

	// 分配码字(按符号序,同码长内符号值小的先分配)
	// MSSDK 改:只输出原始 freq>0 的符号码长(标准 zlib 会输出哑填充节点的码长,
	// MSSDK 不输出)。这影响 distance tree:只有一个真实距离码时,真机只输出 1 个码。
	for n := 0; n <= maxCode; n++ {
		l := treeLen[n]
		if l == 0 || freq[n] == 0 {
			h.codes[n].len = 0
			continue
		}
		h.codes[n] = hcode{
			code: reverseBits(nextCode[l], uint8(l)),
			len:  l,
		}
		nextCode[l]++
	}
}

// bitCounts computes the number of literals assigned to each bit size in the Huffman encoding.
// It is only called when list.length >= 3.
// The cases of 0, 1, and 2 literals are handled by special case code.
//
// list is an array of the literals with non-zero frequencies
// and their associated frequencies. The array is in order of increasing
// frequency and has as its last element a special element with frequency
// MaxInt32.
//
// maxBits is the maximum number of bits that should be used to encode any literal.
// It must be less than 16.
//
// bitCounts returns an integer slice in which slice[i] indicates the number of literals
// that should be encoded in i bits.
func (h *huffmanEncoder) bitCounts(list []literalNode, maxBits int32) []int32 {
	if maxBits >= maxBitsLimit {
		panic("flate: maxBits too large")
	}
	n := int32(len(list))
	list = list[0 : n+1]
	list[n] = maxNode()

	// The tree can't have greater depth than n - 1, no matter what. This
	// saves a little bit of work in some small cases
	if maxBits > n-1 {
		maxBits = n - 1
	}

	// Create information about each of the levels.
	// A bogus "Level 0" whose sole purpose is so that
	// level1.prev.needed==0.  This makes level1.nextPairFreq
	// be a legitimate value that never gets chosen.
	var levels [maxBitsLimit]levelInfo
	// leafCounts[i] counts the number of literals at the left
	// of ancestors of the rightmost node at level i.
	// leafCounts[i][j] is the number of literals at the left
	// of the level j ancestor.
	var leafCounts [maxBitsLimit][maxBitsLimit]int32

	for level := int32(1); level <= maxBits; level++ {
		// For every level, the first two items are the first two characters.
		// We initialize the levels as if we had already figured this out.
		levels[level] = levelInfo{
			level:        level,
			lastFreq:     list[1].freq,
			nextCharFreq: list[2].freq,
			nextPairFreq: list[0].freq + list[1].freq,
		}
		leafCounts[level][level] = 2
		if level == 1 {
			levels[level].nextPairFreq = math.MaxInt32
		}
	}

	// We need a total of 2*n - 2 items at top level and have already generated 2.
	levels[maxBits].needed = 2*n - 4

	level := maxBits
	for {
		l := &levels[level]
		if l.nextPairFreq == math.MaxInt32 && l.nextCharFreq == math.MaxInt32 {
			// We've run out of both leaves and pairs.
			// End all calculations for this level.
			// To make sure we never come back to this level or any lower level,
			// set nextPairFreq impossibly large.
			l.needed = 0
			levels[level+1].nextPairFreq = math.MaxInt32
			level++
			continue
		}

		prevFreq := l.lastFreq
		if l.nextCharFreq < l.nextPairFreq {
			// The next item on this row is a leaf node.
			n := leafCounts[level][level] + 1
			l.lastFreq = l.nextCharFreq
			// Lower leafCounts are the same of the previous node.
			leafCounts[level][level] = n
			l.nextCharFreq = list[n].freq
		} else {
			// The next item on this row is a pair from the previous row.
			// nextPairFreq isn't valid until we generate two
			// more values in the level below
			l.lastFreq = l.nextPairFreq
			// Take leaf counts from the lower level, except counts[level] remains the same.
			copy(leafCounts[level][:level], leafCounts[level-1][:level])
			levels[l.level-1].needed = 2
		}

		if l.needed--; l.needed == 0 {
			// We've done everything we need to do for this level.
			// Continue calculating one level up. Fill in nextPairFreq
			// of that level with the sum of the two nodes we've just calculated on
			// this level.
			if l.level == maxBits {
				// All done!
				break
			}
			levels[l.level+1].nextPairFreq = prevFreq + l.lastFreq
			level++
		} else {
			// If we stole from below, move down temporarily to replenish it.
			for levels[level-1].needed > 0 {
				level--
			}
		}
	}

	// Somethings is wrong if at the end, the top level is null or hasn't used
	// all of the leaves.
	if leafCounts[maxBits][maxBits] != n {
		panic("leafCounts[maxBits][maxBits] != n")
	}

	bitCount := h.bitCount[:maxBits+1]
	bits := 1
	counts := &leafCounts[maxBits]
	for level := maxBits; level > 0; level-- {
		// chain.leafCount gives the number of literals requiring at least "bits"
		// bits to encode.
		bitCount[bits] = counts[level] - counts[level-1]
		bits++
	}
	return bitCount
}

// Look at the leaves and assign them a bit count and an encoding as specified
// in RFC 1951 3.2.2
func (h *huffmanEncoder) assignEncodingAndSize(bitCount []int32, list []literalNode) {
	code := uint16(0)
	for n, bits := range bitCount {
		code <<= 1
		if n == 0 || bits == 0 {
			continue
		}
		// The literals list[len(list)-bits] .. list[len(list)-bits]
		// are encoded using "bits" bits, and get the values
		// code, code + 1, ....  The code values are
		// assigned in literal order (not frequency order).
		chunk := list[len(list)-int(bits):]

		h.lns.sort(chunk)
		for _, node := range chunk {
			h.codes[node.literal] = hcode{code: reverseBits(code, uint8(n)), len: uint16(n)}
			code++
		}
		list = list[0 : len(list)-int(bits)]
	}
}

// Update this Huffman Code object to be the minimum code for the specified frequency count.
//
// freq is an array of frequencies, in which freq[i] gives the frequency of literal i.
// maxBits  The maximum number of bits to use for any literal.
func (h *huffmanEncoder) generate(freq []int32, maxBits int32) {
	// MSSDK 改:用标准 zlib 的 build_tree + gen_bitlen + gen_codes 算法,
	// 替代 Go flate 原始的 level-based bitCounts(两者码长分配不同)。
	h.zlibBuildTree(freq, maxBits)
}

type byLiteral []literalNode

func (s *byLiteral) sort(a []literalNode) {
	*s = byLiteral(a)
	sort.Sort(s)
}

func (s byLiteral) Len() int { return len(s) }

func (s byLiteral) Less(i, j int) bool {
	return s[i].literal < s[j].literal
}

func (s byLiteral) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

type byFreq []literalNode

func (s *byFreq) sort(a []literalNode) {
	*s = byFreq(a)
	sort.Sort(s)
}

func (s byFreq) Len() int { return len(s) }

func (s byFreq) Less(i, j int) bool {
	if s[i].freq == s[j].freq {
		return s[i].literal < s[j].literal
	}
	return s[i].freq < s[j].freq
}

func (s byFreq) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func reverseBits(number uint16, bitLength byte) uint16 {
	return bits.Reverse16(number << (16 - bitLength))
}
