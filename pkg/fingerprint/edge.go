package fingerprint

import (
	"github.com/user/tls-client/internal/h2"
	utls "github.com/refraction-networking/utls"
)

func init() {
	chromeH2 := h2.ChromeDefaultConfig()

	Register(&BrowserProfile{
		Name:          "edge-124-win",
		Browser:       "edge",
		Platform:      "windows",
		Version:       "124.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2:            chromeH2,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	})

	Register(&BrowserProfile{
		Name:          "edge-126-win",
		Browser:       "edge",
		Platform:      "windows",
		Version:       "126.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2:            chromeH2,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
		Tags:          []string{"latest"},
	})

	Register(&BrowserProfile{
		Name:          "edge-126-mac",
		Browser:       "edge",
		Platform:      "macos",
		Version:       "126.0.0.0",
		ClientHelloID: utls.HelloChrome_120,
		H2:            chromeH2,
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
		Tags:          []string{"latest"},
	})
}
