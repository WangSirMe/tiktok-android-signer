package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSM3StandardVectors(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// GB/T 32905-2016 standard vectors.
		{"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		{strings.Repeat("abcd", 16), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
	}
	for _, c := range cases {
		got := SM3Sum([]byte(c.in))
		if hex.EncodeToString(got[:]) != c.want {
			t.Fatalf("SM3(%q)=%x want %s", c.in, got, c.want)
		}
	}
}

func TestSimonReferenceVector(t *testing.T) {
	pt := [2]uint64{0x0123456789abcdef, 0xfedcba9876543210}
	k := [4]uint64{0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444}
	ct := SimonEncryptBlock(pt, k)
	// Cross-checked against the Python reference implementation.
	if ct[0] != 0xc1b73b35be123a0a || ct[1] != 0xd1b2a1f3d0b9a4c3 {
		t.Fatalf("Simon mismatch: got 0x%016x,0x%016x", ct[0], ct[1])
	}
}

func TestXLadonReferenceVector(t *testing.T) {
	// Regression pin for the X-Ladon algorithm, aligned to tr4cex/TikTok-Encryption
	// ladon.py (__ROR__ = plain 64-bit rotate-right). Fixed rand4=01020304 so the
	// output is deterministic; guards against accidental algorithm regressions.
	got := xLadonWithRand(1233, 2142840551, 1700000000, []byte{0x01, 0x02, 0x03, 0x04})
	want := "AQIDBAg9q7y2FKMM0eeGFk1n4W/Q28AxEuIoF+PlPOv0uX8J"
	if got != want {
		t.Fatalf("X-Ladon mismatch:\n got:  %s\n want: %s", got, want)
	}
}

func TestArgusVector(t *testing.T) {
	// 33.2.5 algorithm: verify XArgus produces valid base64 of the expected
	// length (~560 chars with dyn_seed, ~344 without). Exact output is random
	// (per-request random_bytes), so we check structural properties instead.
	params := "aweme_id=7351234567890123456&aid=1233&device_id=1234567890123456789&version_name=33.2.5"
	got := XArgus(params, nil, 1700000000, "1234567890123456789", "33.2.5", DefaultArgusConfig, ArgusExtra{})
	if len(got) < 300 {
		t.Fatalf("X-Argus too short: %d chars", len(got))
	}
	// Must be valid base64 (decodable without error).
	if _, err := base64.StdEncoding.DecodeString(got); err != nil {
		t.Fatalf("X-Argus not valid base64: %v", err)
	}
	// With dyn_seed the output should be ~536 chars(dynEncode payload 统一返回 nil 后,
	// bean[26].2 为空,比旧实现的 12B payload 短约 16B base64)。
	got2 := XArgus(params, nil, 1700000000, "1234567890123456789", "33.2.5", DefaultArgusConfig, ArgusExtra{
		DynSeed:    "MDGkG57Sq3cDIDZ6yT1jwdfhnrQvGH8hVTdz8f1dSx3UehyGFDBrHVZ/REu3NQSm2ekPJQjOwhaYtw7OUPekUwuXxjGIVrEHKtBnmkdE7jRr/pQRFr7ori0UOHuI7t7KX/E=",
		DynVersion: 5,
	})
	if len(got2) < 400 {
		t.Fatalf("X-Argus with dyn_seed too short: %d chars", len(got2))
	}
}

func TestTTEncryptReferenceVector(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i)
	}
	pt := append([]byte{31, 139, 8, 0, 0, 0, 0, 0, 0, 0}, []byte("HELLO_TTENCRYPT_VECTOR_0123456789")...)
	got := hex.EncodeToString(ttEncryptWithSalt(pt, salt[:]))
	want := "746305100000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0d6a108e37df961833b30bb6cec78fbc5f1158b0f72c8b2503ef5ced0d4da7466db895bdb57bebe34df69e5eedb23600fe5054ad833eb2148f37f3c67c3a617b6d33b6eb94bbfe10f6d7b045077015bc248948b0809a4a5c75459a2ce5924a36bb2410a16308b0e98e05c1ffc62ece69"
	if got != want {
		t.Fatalf("TTEncrypt mismatch:\n got:  %s\n want: %s", got, want)
	}
}
