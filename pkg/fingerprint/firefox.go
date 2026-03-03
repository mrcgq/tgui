package fingerprint

import (
	"github.com/user/tls-client/internal/h2"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func init() {
	firefoxH2 := h2.FirefoxDefaultConfig()

	Register(&BrowserProfile{
		Name:          "firefox-121-win",
		Browser:       "firefox",
		Platform:      "windows",
		Version:       "121.0",
		ClientHelloID: utls.HelloFirefox_120,
		H2:            firefoxH2,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	})

	Register(&BrowserProfile{
		Name:          "firefox-124-win",
		Browser:       "firefox",
		Platform:      "windows",
		Version:       "124.0",
		ClientHelloID: utls.HelloFirefox_120,
		H2:            firefoxH2,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
	})

	Register(&BrowserProfile{
		Name:          "firefox-126-linux",
		Browser:       "firefox",
		Platform:      "linux",
		Version:       "126.0",
		ClientHelloID: utls.HelloFirefox_120,
		H2:            firefoxH2,
		UserAgent:     "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	})

	Register(&BrowserProfile{
		Name:          "firefox-127-win",
		Browser:       "firefox",
		Platform:      "windows",
		Version:       "127.0",
		ClientHelloID: utls.HelloFirefox_120,
		H2: h2.FingerprintConfig{
			Settings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 65536},
				{ID: http2.SettingInitialWindowSize, Val: 131072},
				{ID: http2.SettingMaxFrameSize, Val: 16384},
			},
			WindowUpdateValue: 12517377,
			PseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
		},
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
		Tags:      []string{"latest"},
	})

	Register(&BrowserProfile{
		Name:          "firefox-127-mac",
		Browser:       "firefox",
		Platform:      "macos",
		Version:       "127.0",
		ClientHelloID: utls.HelloFirefox_120,
		H2:            firefoxH2,
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
		Tags:          []string{"latest"},
	})
}
