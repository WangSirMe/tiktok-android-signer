package crypto_test

import (
	"testing"

	"github.com/WangSirMe/tiktok-android-signer/crypto"
)

const testUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

func TestGenerateXBogusMatchesPython(t *testing.T) {
	query := "aid=1988&app_name=tiktok_web"
	got := crypto.GenerateXBogus(query, testUA, "", 1700000000)
	want := "DFSzswVOlXsANtyetmWx-e9WX7nf"
	if got != want {
		t.Fatalf("xbogus mismatch with Python:\n got:  %s\n want: %s", got, want)
	}
}

func TestGenerateXBogusDeterministic(t *testing.T) {
	query := "aid=1988&app_name=tiktok_web"
	got := crypto.GenerateXBogus(query, testUA, "", 1700000000)
	if got == "" || len(got) < 20 {
		t.Fatalf("unexpected xbogus: %q", got)
	}
	// 同输入应稳定输出
	got2 := crypto.GenerateXBogus(query, testUA, "", 1700000000)
	if got != got2 {
		t.Fatalf("xbogus not deterministic: %q vs %q", got, got2)
	}
}

func TestGenerateXGnarlyNonEmpty(t *testing.T) {
	query := "aid=1988&app_name=tiktok_web"
	got := crypto.GenerateXGnarly(query, testUA, "")
	if got == "" || len(got) < 20 {
		t.Fatalf("unexpected xgnarly: %q", got)
	}
}

func TestXGorgon0404ReferenceVector(t *testing.T) {
	// 33.2.5 algorithm uses "8404" tag + random header2 + "0000" header3.
	// The body (last 40 hex chars) is deterministic for the same input.
	got := crypto.XGorgon("aweme_id=7351234567890123456&aid=1233", "", "", 1700000000)
	// Body uses params[:4] (not md5(params)[:4]) per the Python reference.
	wantBody := "64a23e765c84d8db89df6506615477a00688ac15"
	if len(got) < 52 {
		t.Fatalf("X-Gorgon too short: %d (%q)", len(got), got)
	}
	if got[:4] != "8404" {
		t.Fatalf("X-Gorgon missing 8404 tag: %q", got)
	}
	if got[8:12] != "0000" {
		t.Fatalf("X-Gorgon missing 0000 separator: %q", got)
	}
	if gotBody := got[len(got)-40:]; gotBody != wantBody {
		t.Fatalf("X-Gorgon body mismatch:\n got:  %s\n want: %s", gotBody, wantBody)
	}
}

func TestXGorgonStructureAndDeterminism(t *testing.T) {
	query := "aweme_id=7351234567890123456&aid=1233&device_platform=android"
	ts := int64(1700000000)

	got := crypto.XGorgon(query, "", "", ts)

	// "8404"(4) + h2(4) + "0000"(4) + 20 bytes hex(40) = 52 chars.
	if len(got) != 52 {
		t.Fatalf("unexpected X-Gorgon length: got %d want 52 (%q)", len(got), got)
	}
	if got[:4] != "8404" {
		t.Fatalf("X-Gorgon missing v8404 tag: %q", got)
	}
	if got[8:12] != "0000" {
		t.Fatalf("X-Gorgon missing 0000 separator: %q", got)
	}
	// Body is deterministic; header2 is random so full string differs between calls.
	gotBody := got[12:]
	if got2 := crypto.XGorgon(query, "", "", ts); got2[12:] != gotBody {
		t.Fatalf("X-Gorgon body not deterministic: %q vs %q", gotBody, got2[12:])
	}
	// Timestamp participates in the signature: a different ts must change body.
	if other := crypto.XGorgon(query, "", "", ts+1); other[12:] == gotBody {
		t.Fatalf("X-Gorgon ignores timestamp: %q", gotBody)
	}
	// Query participates in the signature: params[:4] changes when query changes.
	if other := crypto.XGorgon("different_query_starts_here", "", "", ts); other[12:] == gotBody {
		t.Fatalf("X-Gorgon ignores query: %q", gotBody)
	}
}

func TestXKhronos(t *testing.T) {
	if got := crypto.XKhronos(1700000000); got != "1700000000" {
		t.Fatalf("unexpected X-Khronos: %q", got)
	}
}
