package native

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// buildDeviceDetail 从「hex 模板 + bytes.Replace」重构为「ttdevice.DeviceInfo proto
// struct + proto.Marshal」后的不变量测试。
//
// 重构动机:原方案的 msTokenDeviceDetailCDID 常量曾与 hex 模板内 field 26 真实字节
// 差 1 个字符(...a1a4d7 vs ...a1f4d7),导致 bytes.Replace 永久 no-op,动态 cdid
// 从未真正写入 get_token 请求。struct 方案下 cdid 直接赋给 InstallUuid 字段,从根上
// 消除该类隐患;以下三测试锁定重构后的行为契约。

// deviceDetailLen 是固定设备档(MI 6X)经 proto.Marshal 的字节数,对齐历史 hex 模板。
// 该 message 无任何字段等于 proto3 默认值,故 marshal 输出逐字节稳定。
const deviceDetailLen = 605

// extractProtoFieldCount 统计 protobuf wire 顶层字段数。
func extractProtoFieldCount(t *testing.T, data []byte) int {
	t.Helper()
	n := 0
	for len(data) > 0 {
		_, typ, m := protowire.ConsumeTag(data)
		if m < 0 {
			t.Fatalf("ConsumeTag: %v", protowire.ParseError(m))
		}
		data = data[m:]
		switch typ {
		case protowire.VarintType:
			_, mm := protowire.ConsumeVarint(data)
			data = data[mm:]
		case protowire.BytesType:
			_, mm := protowire.ConsumeBytes(data)
			data = data[mm:]
		case protowire.Fixed32Type:
			_, mm := protowire.ConsumeFixed32(data)
			data = data[mm:]
		case protowire.Fixed64Type:
			_, mm := protowire.ConsumeFixed64(data)
			data = data[mm:]
		}
		n++
	}
	return n
}

// extractProtoFieldValue 返回首个匹配 field 号的 LEN 字段 payload。
func extractProtoFieldValue(t *testing.T, data []byte, field int) []byte {
	t.Helper()
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			t.Fatalf("ConsumeTag: %v", protowire.ParseError(n))
		}
		data = data[n:]
		switch typ {
		case protowire.VarintType:
			_, m := protowire.ConsumeVarint(data)
			data = data[m:]
		case protowire.BytesType:
			b, m := protowire.ConsumeBytes(data)
			data = data[m:]
			if int(num) == field {
				return b
			}
		case protowire.Fixed32Type:
			_, m := protowire.ConsumeFixed32(data)
			data = data[m:]
		case protowire.Fixed64Type:
			_, m := protowire.ConsumeFixed64(data)
			data = data[m:]
		}
	}
	return nil
}

// TestBuildDeviceDetail_ReplacesCDID 验证动态 cdid 真正进入 field 26。
// 这是原 bytes.Replace no-op bug 的回归测试。
func TestBuildDeviceDetail_ReplacesCDID(t *testing.T) {
	const newCDID = "11111111-2222-3333-4444-555555555555"
	out := buildDeviceDetail(newCDID)
	got := string(extractProtoFieldValue(t, out, 26))
	if got != newCDID {
		t.Fatalf("field 26 = %q, want %q(动态 cdid 未写入)", got, newCDID)
	}
}

// TestBuildDeviceDetail_LengthInvariant 验证固定设备档输出长度恒为 605B。
// 该 message 后续进 MSSEncode(zlib+TEA+AES),字节布局必须稳定。
func TestBuildDeviceDetail_LengthInvariant(t *testing.T) {
	out := buildDeviceDetail("69e6853f-30ea-4410-a6dd-5dec29a1f4d7")
	if len(out) != deviceDetailLen {
		t.Fatalf("长度 = %d, want %d", len(out), deviceDetailLen)
	}
}

// TestBuildDeviceDetail_FieldCount 验证 55 个字段全部写入(防止手抖漏填)。
func TestBuildDeviceDetail_FieldCount(t *testing.T) {
	out := buildDeviceDetail("69e6853f-30ea-4410-a6dd-5dec29a1f4d7")
	const wantFields = 55
	if got := extractProtoFieldCount(t, out); got != wantFields {
		t.Fatalf("字段数 = %d, want %d(可能有字段漏填或 proto3 默认值省略)", got, wantFields)
	}
}

// TestBuildDeviceDetail_EmptyCDID 验证空 cdid 走占位路径不 panic。
func TestBuildDeviceDetail_EmptyCDID(t *testing.T) {
	out := buildDeviceDetail("")
	if len(out) != deviceDetailLen {
		t.Fatalf("空 cdid 长度 = %d, want %d", len(out), deviceDetailLen)
	}
}
