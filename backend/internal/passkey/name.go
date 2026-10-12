package passkey

import (
	"encoding/hex"
	"strings"
)

const unknownPasskeyName = "不明なパスキー"

// DisplayName は登録完了時の表示名を決める。
// 既知の AAGUID ならパスキーの保存先（Apple Passwords や Google Password Manager など）。
// AAGUID がゼロのときは User-Agent から端末とブラウザを付ける。
// ゼロでない未知の AAGUID は、User-Agent が別の端末を指すことがあるため使わない。
// 登録時にユーザーへ名前を尋ねない。
func DisplayName(aaguid []byte, userAgent string) string {
	if len(aaguid) == 16 && !isZeroAAGUID(aaguid) {
		if name, ok := providerNames[formatAAGUID(aaguid)]; ok && name != "" {
			return name
		}
		return unknownPasskeyName
	}
	if label := clientLabel(userAgent); label != "" {
		return label
	}
	return unknownPasskeyName
}

func isZeroAAGUID(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func formatAAGUID(b []byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf[:])
}

func clientLabel(userAgent string) string {
	device := deviceFromUA(userAgent)
	browser := browserFromUA(userAgent)
	switch {
	case device != "" && browser != "":
		return device + " の " + browser
	case device != "":
		return device
	default:
		return browser
	}
}

func deviceFromUA(ua string) string {
	switch {
	case strings.Contains(ua, "iPhone"):
		return "iPhone"
	case strings.Contains(ua, "iPad"):
		return "iPad"
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "CrOS"):
		return "ChromeOS"
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Macintosh"):
		return "Mac"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	default:
		return ""
	}
}

func browserFromUA(ua string) string {
	switch {
	case strings.Contains(ua, "Edg/") || strings.Contains(ua, "EdgiOS/"):
		return "Edge"
	case strings.Contains(ua, "FxiOS/") || strings.Contains(ua, "Firefox/"):
		return "Firefox"
	case strings.Contains(ua, "CriOS/") || strings.Contains(ua, "Chrome/"):
		return "Chrome"
	case strings.Contains(ua, "Safari/"):
		return "Safari"
	default:
		return ""
	}
}
