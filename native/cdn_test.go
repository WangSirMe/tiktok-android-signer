package native

import "testing"

func TestIsOpenCDN_regionalVariants(t *testing.T) {
	cases := []struct {
		name string
		url  string
		open bool
	}{
		{"tiktokcdn.com base domain", "https://v16.tiktokcdn.com/foo.mp4", true},
		{"tiktokcdn-us.com regional variant", "https://v16m.tiktokcdn-us.com/foo.mp3", true},
		{"tiktokv.com", "https://v16.tiktokv.com/foo.mp4", true},
		{"play API", "https://www.tiktok.com/aweme/v1/play/?video_id=1", false},
		{"gated webapp-prime exact", "https://webapp-prime.tiktok.com/video/tos/foo", false},
		{"gated webapp-prime with region segment", "https://v16-webapp-prime.us.tiktok.com/video/tos/foo", false},
		{"gated web-newkey", "https://v16-web-newkey.tiktokcdn.com/foo.mp4", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsOpenCDN(c.url); got != c.open {
				t.Fatalf("IsOpenCDN(%q) = %v, want %v", c.url, got, c.open)
			}
		})
	}
}
