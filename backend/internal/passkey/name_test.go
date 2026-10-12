package passkey

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestDisplayName(t *testing.T) {
	chromeMac := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	safariMac := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
	safariPhone := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
	chromePhone := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.0.0 Mobile/15E148 Safari/604.1"
	edgeWin := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
	android := "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

	tests := []struct {
		name      string
		aaguid    string
		userAgent string
		want      string
	}{
		{name: "google password manager", aaguid: "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", userAgent: chromeMac, want: "Google Password Manager"},
		{name: "apple passwords", aaguid: "fbfc3007-154e-4ecc-8c0b-6e020557d7bd", userAgent: safariMac, want: "Apple Passwords"},
		{name: "zero aaguid uses browser and device", aaguid: "00000000-0000-0000-0000-000000000000", userAgent: safariMac, want: "Mac の Safari"},
		{name: "iphone safari", userAgent: safariPhone, want: "iPhone の Safari"},
		{name: "iphone chrome", userAgent: chromePhone, want: "iPhone の Chrome"},
		{name: "edge is not chrome", userAgent: edgeWin, want: "Windows の Edge"},
		{name: "android before linux", userAgent: android, want: "Android の Chrome"},
		{name: "unknown aaguid ignores user agent", aaguid: "11111111-1111-1111-1111-111111111111", userAgent: chromeMac, want: unknownPasskeyName},
		{name: "missing signals", want: unknownPasskeyName},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DisplayName(parseAAGUID(t, tt.aaguid), tt.userAgent)
			if got != tt.want {
				t.Fatalf("DisplayName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func parseAAGUID(t *testing.T, id string) []byte {
	t.Helper()
	if id == "" {
		return nil
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
