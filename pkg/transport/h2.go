package transport

import (
	"fmt"
	"net"
)

// H2Transport 使用 WebSocket 协议实现隧道
// 注意：虽然名为 "h2"，但实际改用 WebSocket 以确保与 CF Workers 兼容
type H2Transport struct{}

func (t *H2Transport) Name() string { return "h2" }

func (t *H2Transport) ALPNProtos() []string { return []string{"http/1.1"} }

func (t *H2Transport) Info() TransportInfo {
	return TransportInfo{
		SupportsMultiplex: false,
		SupportsBinary:    true,
		RequiresUpgrade:   true,
		MaxFrameSize:      16384,
	}
}

func (t *H2Transport) Wrap(conn net.Conn, cfg *Config) (net.Conn, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	// 使用 WebSocket 握手
	wsT := &WSTransport{}
	wsConn, err := wsT.Wrap(conn, cfg)
	if err != nil {
		return nil, fmt.Errorf("h2: ws upgrade failed: %w", err)
	}

	return wsConn, nil
}
