package fingerprint

import (
	"github.com/user/tls-client/internal/h2"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func init() {
	chromeH2 := h2.ChromeDefaultConfig()

	Register(&BrowserProfile{
		Name:          "chrome-120-win",
		Browser:       "chrome",
		Platform:      "windows",
		Version:       "120.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2:            chromeH2,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	})

	Register(&BrowserProfile{
		Name:          "chrome-123-win",
		Browser:       "chrome",
		Platform:      "windows",
		Version:       "123.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2:            chromeH2,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	})

	Register(&BrowserProfile{
		Name:          "chrome-124-win",
		Browser:       "chrome",
		Platform:      "windows",
		Version:       "124.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2:            chromeH2,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	})

	Register(&BrowserProfile{
		Name:          "chrome-125-win",
		Browser:       "chrome",
		Platform:      "windows",
		Version:       "125.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2:            chromeH2,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	})

	Register(&BrowserProfile{
		Name:          "chrome-126-win",
		Browser:       "chrome",
		Platform:      "windows",
		Version:       "126.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2:            chromeH2,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		Tags:          []string{"latest", "recommended", "default"},
	})

	Register(&BrowserProfile{
		Name:          "chrome-126-mac",
		Browser:       "chrome",
		Platform:      "macos",
		Version:       "126.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2:            chromeH2,
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		Tags:          []string{"latest"},
	})

	Register(&BrowserProfile{
		Name:          "chrome-124-mac",
		Browser:       "chrome",
		Platform:      "macos",
		Version:       "124.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2:            chromeH2,
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	})

	Register(&BrowserProfile{
		Name:          "chrome-126-android",
		Browser:       "chrome",
		Platform:      "android",
		Version:       "126.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2: h2.FingerprintConfig{
			Settings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 65536},
				{ID: http2.SettingEnablePush, Val: 0},
				{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
				{ID: http2.SettingInitialWindowSize, Val: 6291456},
				{ID: http2.SettingMaxHeaderListSize, Val: 262144},
			},
			WindowUpdateValue: 15663105,
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		},
		UserAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
		Tags:      []string{"latest", "mobile"},
	})
}
