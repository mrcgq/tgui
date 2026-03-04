package transport

import "net"

// RawTransport 裸 TLS 传输
type RawTransport struct{}

func (t *RawTransport) Name() string         { return "raw" }
func (t *RawTransport) ALPNProtos() []string { return []string{"http/1.1"} }

func (t *RawTransport) Info() TransportInfo {
	return TransportInfo{
		SupportsMultiplex: false,
		SupportsBinary:    true,
		RequiresUpgrade:   false,
		MaxFrameSize:      0,
	}
}

func (t *RawTransport) Wrap(conn net.Conn, _ *Config) (net.Conn, error) {
	return conn, nil
}
