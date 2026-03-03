package fingerprint

import (
	"fmt"

	"github.com/user/tls-client/internal/h2"
	utls "github.com/refraction-networking/utls"
)

type BrowserProfile struct {
	Name            string
	Browser         string
	Platform        string
	Version         string
	ClientHelloID   utls.ClientHelloID
	H2              h2.FingerprintConfig
	UserAgent       string
	ExpectedJA3Hash string
	ExpectedJA4Hash string
	ExpectedH2FP    string
	Tags            []string
}

func (p *BrowserProfile) HasTag(tag string) bool {
	for _, t := range p.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (p *BrowserProfile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("fingerprint: profile name is required")
	}
	if p.Browser == "" {
		return fmt.Errorf("fingerprint: profile %q: browser is required", p.Name)
	}
	if p.Platform == "" {
		return fmt.Errorf("fingerprint: profile %q: platform is required", p.Name)
	}
	if p.UserAgent == "" {
		return fmt.Errorf("fingerprint: profile %q: user agent is required", p.Name)
	}
	if err := p.H2.Validate(); err != nil {
		return fmt.Errorf("fingerprint: profile %q: %w", p.Name, err)
	}
	return nil
}

func (p *BrowserProfile) H2Fingerprint() string {
	return p.H2.Fingerprint()
}
