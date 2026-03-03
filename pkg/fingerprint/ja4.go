package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// JA4Result holds computed JA4 fingerprint components.
type JA4Result struct {
	JA4      string
	JA4H     string
	Protocol string
	TLSVersion  string
	SNI         string
	CipherCount string
	ExtCount    string
	ALPN        string
}

// ComputeJA4H computes the JA4H (HTTP/2) fingerprint from a BrowserProfile.
func ComputeJA4H(p *BrowserProfile) string {
	settingParts := make([]string, 0, len(p.H2.Settings))
	for _, s := range p.H2.Settings {
		settingParts = append(settingParts, fmt.Sprintf("%d=%d", s.ID, s.Val))
	}

	wu := fmt.Sprintf("%d", p.H2.WindowUpdateValue)

	pseudoAbbrev := make([]string, 0, len(p.H2.PseudoHeaderOrder))
	for _, h := range p.H2.PseudoHeaderOrder {
		switch h {
		case ":method":
			pseudoAbbrev = append(pseudoAbbrev, "m")
		case ":authority":
			pseudoAbbrev = append(pseudoAbbrev, "a")
		case ":scheme":
			pseudoAbbrev = append(pseudoAbbrev, "s")
		case ":path":
			pseudoAbbrev = append(pseudoAbbrev, "p")
		}
	}

	raw := strings.Join(settingParts, ",") + "_" + wu + "_" + strings.Join(pseudoAbbrev, "")

	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])[:12]
}

// ComputeJA4HRaw returns the raw (unhashed) JA4H string for debugging.
func ComputeJA4HRaw(p *BrowserProfile) string {
	parts := make([]string, 0, len(p.H2.Settings))
	for _, s := range p.H2.Settings {
		parts = append(parts, fmt.Sprintf("%d=%d", s.ID, s.Val))
	}
	return fmt.Sprintf("%s|%d|%s",
		strings.Join(parts, ","),
		p.H2.WindowUpdateValue,
		strings.Join(p.H2.PseudoHeaderOrder, ","),
	)
}

// CompareH2Fingerprints checks if two profiles have identical H2 fingerprints.
func CompareH2Fingerprints(a, b *BrowserProfile) bool {
	return a.H2.Fingerprint() == b.H2.Fingerprint()
}

// DetectGoDefault checks if a profile's H2 settings match Go's default.
func DetectGoDefault(p *BrowserProfile) bool {
	for _, s := range p.H2.Settings {
		if s.ID == 0x01 && s.Val == 4096 {
			if p.H2.WindowUpdateValue == 1073741823 {
				return true
			}
		}
	}
	return false
}
