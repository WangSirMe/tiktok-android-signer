package crypto

import "sort"

// Minimal protobuf wire-format encoder for the X-Argus message. Supports the
// field types used by the Argus bean: varint (int), length-delimited (string,
// bytes, nested message). Matches the reference encoder, including its
// non-standard varint loop (`while v > 0x80`).

// pbValue is one of: int64 (varint), string, []byte, or pbMessage (nested).
type pbValue interface{}

// pbMessage maps field index → value, encoded in ascending field order.
type pbMessage map[int]pbValue

// pbWriteVarint reproduces the reference write_varint, which uses `> 0x80`
// (not `>=`). This diverges from canonical protobuf only when an intermediate
// 7-bit group lands exactly on 0x80, but must be matched byte-for-byte.
func pbWriteVarint(buf []byte, v uint64) []byte {
	for v > 0x80 {
		buf = append(buf, byte(v&0x7F)|0x80)
		v >>= 7
	}
	return append(buf, byte(v&0x7F))
}

func pbWriteString(buf, data []byte) []byte {
	buf = pbWriteVarint(buf, uint64(len(data)))
	return append(buf, data...)
}

// pbEncode serializes a message to protobuf bytes (fields in ascending order).
func pbEncode(msg pbMessage) []byte {
	idxs := make([]int, 0, len(msg))
	for k := range msg {
		idxs = append(idxs, k)
	}
	sort.Ints(idxs)

	var buf []byte
	for _, idx := range idxs {
		v := msg[idx]
		switch val := v.(type) {
		case int:
			buf = pbWriteVarint(buf, uint64(idx<<3)|0)
			buf = pbWriteVarint(buf, uint64(val))
		case int64:
			buf = pbWriteVarint(buf, uint64(idx<<3)|0)
			buf = pbWriteVarint(buf, uint64(val))
		case uint64:
			buf = pbWriteVarint(buf, uint64(idx<<3)|0)
			buf = pbWriteVarint(buf, val)
		case string:
			buf = pbWriteVarint(buf, uint64(idx<<3)|2)
			buf = pbWriteString(buf, []byte(val))
		case []byte:
			buf = pbWriteVarint(buf, uint64(idx<<3)|2)
			buf = pbWriteString(buf, val)
		case pbMessage:
			buf = pbWriteVarint(buf, uint64(idx<<3)|2)
			buf = pbWriteString(buf, pbEncode(val))
		default:
			panic("pbEncode: unsupported field type")
		}
	}
	return buf
}
