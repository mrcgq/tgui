package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	socks5VersionOut    = 0x05
	socks5AuthNoneOut   = 0x00
	socks5AuthPassOut   = 0x02
	socks5CmdConnectOut = 0x01
	socks5AtypIPv4Out   = 0x01
	socks5AtypDomainOut = 0x03
	socks5AtypIPv6Out   = 0x04
)

// SOCKS5OutTransport 连接上游 SOCKS5 代理
type SOCKS5OutTransport struct {
	ProxyAddr string
	Username  string
	Password  string
}

func (t *SOCKS5OutTransport) Name() string         { return "socks5-out" }
func (t *SOCKS5OutTransport) ALPNProtos() []string { return []string{"http/1.1"} }

func (t *SOCKS5OutTransport) Info() TransportInfo {
	return TransportInfo{
		SupportsMultiplex: false,
		SupportsBinary:    true,
		RequiresUpgrade:   true,
		MaxFrameSize:      0,
	}
}

func (t *SOCKS5OutTransport) Wrap(conn net.Conn, cfg *Config) (net.Conn, error) {
	if cfg == nil || cfg.Target == "" {
		return nil, fmt.Errorf("socks5-out: target is required")
	}

	targetHost, targetPortStr, err := net.SplitHostPort(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("socks5-out: invalid target %q: %w", cfg.Target, err)
	}
	targetPort, _ := strconv.Atoi(targetPortStr)

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	authMethods := []byte{socks5AuthNoneOut}
	if t.Username != "" && t.Password != "" {
		authMethods = []byte{socks5AuthNoneOut, socks5AuthPassOut}
	}

	greeting := make([]byte, 2+len(authMethods))
	greeting[0] = socks5VersionOut
	greeting[1] = byte(len(authMethods))
	copy(greeting[2:], authMethods)

	if _, err := conn.Write(greeting); err != nil {
		return nil, fmt.Errorf("socks5-out: write greeting: %w", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		return nil, fmt.Errorf("socks5-out: read auth response: %w", err)
	}
	if authResp[0] != socks5VersionOut {
		return nil, fmt.Errorf("socks5-out: invalid version %d", authResp[0])
	}

	switch authResp[1] {
	case socks5AuthNoneOut:
	case socks5AuthPassOut:
		if err := t.doUserPassAuth(conn); err != nil {
			return nil, err
		}
	case 0xFF:
		return nil, fmt.Errorf("socks5-out: no acceptable auth method")
	default:
		return nil, fmt.Errorf("socks5-out: unsupported auth method %d", authResp[1])
	}

	connectReq := t.buildConnectRequest(targetHost, targetPort)
	if _, err := conn.Write(connectReq); err != nil {
		return nil, fmt.Errorf("socks5-out: write connect: %w", err)
	}

	if err := t.readConnectResponse(conn); err != nil {
		return nil, err
	}

	return conn, nil
}

func (t *SOCKS5OutTransport) doUserPassAuth(conn net.Conn) error {
	authReq := make([]byte, 3+len(t.Username)+len(t.Password))
	authReq[0] = 0x01
	authReq[1] = byte(len(t.Username))
	copy(authReq[2:], t.Username)
	authReq[2+len(t.Username)] = byte(len(t.Password))
	copy(authReq[3+len(t.Username):], t.Password)

	if _, err := conn.Write(authReq); err != nil {
		return fmt.Errorf("socks5-out: write auth: %w", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		return fmt.Errorf("socks5-out: read auth result: %w", err)
	}

	if authResp[1] != 0x00 {
		return fmt.Errorf("socks5-out: auth failed (status %d)", authResp[1])
	}

	return nil
}

func (t *SOCKS5OutTransport) buildConnectRequest(host string, port int) []byte {
	var req []byte

	ip := net.ParseIP(host)

	if ip4 := ip.To4(); ip4 != nil {
		req = make([]byte, 10)
		req[0] = socks5VersionOut
		req[1] = socks5CmdConnectOut
		req[2] = 0x00
		req[3] = socks5AtypIPv4Out
		copy(req[4:8], ip4)
		binary.BigEndian.PutUint16(req[8:], uint16(port))
	} else if ip != nil {
		req = make([]byte, 22)
		req[0] = socks5VersionOut
		req[1] = socks5CmdConnectOut
		req[2] = 0x00
		req[3] = socks5AtypIPv6Out
		copy(req[4:20], ip.To16())
		binary.BigEndian.PutUint16(req[20:], uint16(port))
	} else {
		hostBytes := []byte(host)
		req = make([]byte, 7+len(hostBytes))
		req[0] = socks5VersionOut
		req[1] = socks5CmdConnectOut
		req[2] = 0x00
		req[3] = socks5AtypDomainOut
		req[4] = byte(len(hostBytes))
		copy(req[5:], hostBytes)
		binary.BigEndian.PutUint16(req[5+len(hostBytes):], uint16(port))
	}

	return req
}

func (t *SOCKS5OutTransport) readConnectResponse(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("socks5-out: read response: %w", err)
	}

	if header[0] != socks5VersionOut {
		return fmt.Errorf("socks5-out: invalid response version")
	}

	if header[1] != 0x00 {
		errMsgs := map[byte]string{
			0x01: "general failure",
			0x02: "connection not allowed",
			0x03: "network unreachable",
			0x04: "host unreachable",
			0x05: "connection refused",
			0x06: "TTL expired",
			0x07: "command not supported",
			0x08: "address type not supported",
		}
		msg := errMsgs[header[1]]
		if msg == "" {
			msg = fmt.Sprintf("unknown error %d", header[1])
		}
		return fmt.Errorf("socks5-out: connect failed: %s", msg)
	}

	atyp := header[3]
	var addrLen int
	switch atyp {
	case socks5AtypIPv4Out:
		addrLen = 4
	case socks5AtypIPv6Out:
		addrLen = 16
	case socks5AtypDomainOut:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		addrLen = int(lenBuf[0])
	default:
		return fmt.Errorf("socks5-out: unknown atyp %d", atyp)
	}

	remaining := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, remaining); err != nil {
		return err
	}

	return nil
}

// DialSOCKS5 直接通过 SOCKS5 代理拨号
func DialSOCKS5(proxyAddr, target, username, password string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial proxy: %w", err)
	}

	transport := &SOCKS5OutTransport{
		ProxyAddr: proxyAddr,
		Username:  username,
		Password:  password,
	}

	cfg := &Config{Target: target}

	wrappedConn, err := transport.Wrap(conn, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return wrappedConn, nil
}
