package verify

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// Mode defines certificate verification behavior.
type Mode string

const (
	ModeStrict   Mode = "strict"
	ModeSNISkip  Mode = "sni-skip"
	ModeInsecure Mode = "insecure"
	ModePin      Mode = "pin"
)

// Options holds additional verification options.
type Options struct {
	CustomRoots    *x509.CertPool
	PinnedCertHash string
}

// ParseMode parses a string into a Mode value.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeStrict, ModeSNISkip, ModeInsecure, ModePin:
		return Mode(s), nil
	case "":
		return ModeSNISkip, nil
	default:
		return "", fmt.Errorf("verify: unknown mode %q", s)
	}
}

// ApplyToTLSConfig configures certificate verification on a tls.Config.
func ApplyToTLSConfig(cfg *tls.Config, mode Mode, sni string, opts *Options) {
	cfg.ServerName = sni

	if opts == nil {
		opts = &Options{}
	}

	switch mode {
	case ModeStrict:
		cfg.InsecureSkipVerify = false
		if opts.CustomRoots != nil {
			cfg.RootCAs = opts.CustomRoots
		}

	case ModeSNISkip:
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("verify[sni-skip]: no certificates")
			}
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, raw := range rawCerts {
				c, err := x509.ParseCertificate(raw)
				if err != nil {
					return fmt.Errorf("verify[sni-skip]: parse cert %d: %w", i, err)
				}
				certs[i] = c
			}
			verifyOpts := x509.VerifyOptions{
				Intermediates: x509.NewCertPool(),
			}
			if opts.CustomRoots != nil {
				verifyOpts.Roots = opts.CustomRoots
			}
			for _, c := range certs[1:] {
				verifyOpts.Intermediates.AddCert(c)
			}
			_, err := certs[0].Verify(verifyOpts)
			if err != nil {
				return fmt.Errorf("verify[sni-skip]: chain failed: %w", err)
			}
			return nil
		}

	case ModePin:
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("verify[pin]: no certificates")
			}
			hash := sha256.Sum256(rawCerts[0])
			actualPin := hex.EncodeToString(hash[:])
			if opts.PinnedCertHash != "" && actualPin != opts.PinnedCertHash {
				return fmt.Errorf("verify[pin]: pin mismatch")
			}
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, raw := range rawCerts {
				c, err := x509.ParseCertificate(raw)
				if err != nil {
					return fmt.Errorf("verify[pin]: parse cert %d: %w", i, err)
				}
				certs[i] = c
			}
			verifyOpts := x509.VerifyOptions{
				Intermediates: x509.NewCertPool(),
			}
			if opts.CustomRoots != nil {
				verifyOpts.Roots = opts.CustomRoots
			}
			for _, c := range certs[1:] {
				verifyOpts.Intermediates.AddCert(c)
			}
			_, err := certs[0].Verify(verifyOpts)
			return err
		}

	case ModeInsecure:
		cfg.InsecureSkipVerify = true
	}
}
