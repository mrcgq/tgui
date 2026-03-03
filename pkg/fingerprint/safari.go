package fingerprint

import (
	"github.com/user/tls-client/internal/h2"
	utls "github.com/refraction-networking/utls"
)

func init() {
	safariH2 := h2.SafariDefaultConfig()

	Register(&BrowserProfile{
		Name:          "safari-17-mac",
		Browser:       "safari",
		Platform:      "macos",
		Version:       "17.4.1",
		ClientHelloID: utls.HelloIOS_Auto,
		H2:            safariH2,
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	})

	Register(&BrowserProfile{
		Name:          "safari-17-ios",
		Browser:       "safari",
		Platform:      "ios",
		Version:       "17.4.1",
		ClientHelloID: utls.HelloIOS_Auto,
		H2:            safariH2,
		UserAgent:     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
		Tags:          []string{"mobile"},
	})

	Register(&BrowserProfile{
		Name:          "safari-175-mac",
		Browser:       "safari",
		Platform:      "macos",
		Version:       "17.5",
		ClientHelloID: utls.HelloIOS_Auto,
		H2:            safariH2,
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		Tags:          []string{"latest"},
	})

	Register(&BrowserProfile{
		Name:          "safari-175-ios",
		Browser:       "safari",
		Platform:      "ios",
		Version:       "17.5",
		ClientHelloID: utls.HelloIOS_Auto,
		H2:            safariH2,
		UserAgent:     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		Tags:          []string{"latest", "mobile"},
	})
}
