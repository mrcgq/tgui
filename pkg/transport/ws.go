package transport

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WSTransport wraps a TLS connection with WebSocket framing.
type WSTransport struct{}

func (t *WSTransport) Name() string         { return "ws" }
func (t *WSTransport) ALPNProtos() []string { return []string{"http/1.1"} }

func (t *WSTransport) Info() TransportInfo {
	return TransportInfo{
		SupportsMultiplex: false,
		SupportsBinary:    true,
		RequiresUpgrade:   true,
		MaxFrameSize:      16384,
	}
}

func (t *WSTransport) Wrap(conn net.Conn, cfg *Config) (net.Conn, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	cfg.Normalize()

	path := cfg.Path
	if path == "" {
		path = "/"
	}
	host := cfg.Host
	if host == "" {
		host = "localhost"
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("ws: generate key: %w", err)
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	reqStr := fmt.Sprintf("GET %s HTTP/1.1\r\n", path)
	reqStr += fmt.Sprintf("Host: %s\r\n", host)
	reqStr += "Upgrade: websocket\r\n"
	reqStr += "Connection: Upgrade\r\n"
	reqStr += fmt.Sprintf("Sec-WebSocket-Key: %s\r\n", wsKey)
	reqStr += "Sec-WebSocket-Version: 13\r\n"

	if cfg.UserAgent != "" {
		reqStr += fmt.Sprintf("User-Agent: %s\r\n", cfg.UserAgent)
	}

	reqStr += fmt.Sprintf("Origin: https://%s\r\n", host)

	for k, v := range cfg.Headers {
		reqStr += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	reqStr += "\r\n"

	if _, err := conn.Write([]byte(reqStr)); err != nil {
		return nil, fmt.Errorf("ws: send upgrade: %w", err)
	}

	br := bufio.NewReaderSize(conn, 4096)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("ws: read upgrade response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("ws: upgrade failed: %s", resp.Status)
	}

	expectedAccept := computeAcceptKey(wsKey)
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		return nil, fmt.Errorf("ws: invalid Sec-WebSocket-Accept")
	}

	ws := newWSConn(conn, br)

	// 发送 Xlink 协议头
	if cfg.Target != "" {
		xlinkHeader := buildXlinkHeader(cfg.Target, cfg.SOCKS5Proxy, cfg.Fallback)
		if _, err := ws.Write(xlinkHeader); err != nil {
			ws.Close()
			return nil, fmt.Errorf("ws: send xlink header: %w", err)
		}
	}

	go ws.keepAlive()

	return ws, nil
}

func buildXlinkHeader(target, socks5, fallback string) []byte {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = "443"
	}

	port := 443
	if p, err := parsePort(portStr); err == nil {
		port = p
	}

	hostBytes := []byte(host)
	s5Bytes := []byte(socks5)
	fbBytes := []byte(fallback)

	if len(hostBytes) > 255 {
		hostBytes = hostBytes[:255]
	}
	if len(s5Bytes) > 255 {
		s5Bytes = s5Bytes[:255]
	}
	if len(fbBytes) > 255 {
		fbBytes = fbBytes[:255]
	}

	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(hostBytes)))
	buf.Write(hostBytes)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	buf.Write(portBytes)

	buf.WriteByte(byte(len(s5Bytes)))
	if len(s5Bytes) > 0 {
		buf.Write(s5Bytes)
	}

	buf.WriteByte(byte(len(fbBytes)))
	if len(fbBytes) > 0 {
		buf.Write(fbBytes)
	}

	return buf.Bytes()
}

func parsePort(s string) (int, error) {
	var port int
	_, err := fmt.Sscanf(s, "%d", &port)
	if err != nil || port < 1 || port > 65535 {
		return 443, fmt.Errorf("invalid port: %s", s)
	}
	return port, nil
}

func computeAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(wsMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type wsConn struct {
	conn    net.Conn
	br      *bufio.Reader
	writeMu sync.Mutex

	fragmentBuf []byte
	fragmenting bool

	lastPong  atomic.Int64
	closeCh   chan struct{}
	closeOnce sync.Once

	readBuf []byte
	readEOF bool
}

func newWSConn(conn net.Conn, br *bufio.Reader) *wsConn {
	c := &wsConn{
		conn:    conn,
		br:      br,
		closeCh: make(chan struct{}),
	}
	c.lastPong.Store(time.Now().UnixNano())
	return c
}

func (c *wsConn) keepAlive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			lastPong := time.Unix(0, c.lastPong.Load())
			if time.Since(lastPong) > 90*time.Second {
				_ = c.Close()
				return
			}

			c.writeMu.Lock()
			pingData := make([]byte, 8)
			_, _ = rand.Read(pingData)
			_, _ = writeFrame(c.conn, 0x09, pingData)
			c.writeMu.Unlock()
		}
	}
}

func (c *wsConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	if c.readEOF {
		return 0, io.EOF
	}

	for {
		opcode, payload, fin, err := readFrame(c.br)
		if err != nil {
			c.readEOF = true
			return 0, err
		}

		switch opcode {
		case 0x00:
			if c.fragmenting {
				c.fragmentBuf = append(c.fragmentBuf, payload...)
				if fin {
					c.fragmenting = false
					payload = c.fragmentBuf
					c.fragmentBuf = nil
				} else {
					continue
				}
			} else {
				continue
			}

		case 0x01, 0x02:
			if !fin {
				c.fragmenting = true
				c.fragmentBuf = append([]byte(nil), payload...)
				continue
			}

		case 0x08:
			c.readEOF = true
			c.writeMu.Lock()
			_, _ = writeCloseFrame(c.conn, 1000)
			c.writeMu.Unlock()
			return 0, io.EOF

		case 0x09:
			c.writeMu.Lock()
			_, _ = writeFrame(c.conn, 0x0A, payload)
			c.writeMu.Unlock()
			continue

		case 0x0A:
			c.lastPong.Store(time.Now().UnixNano())
			continue

		default:
			continue
		}

		if len(payload) == 0 {
			continue
		}

		n := copy(p, payload)
		if n < len(payload) {
			c.readBuf = make([]byte, len(payload)-n)
			copy(c.readBuf, payload[n:])
		}
		return n, nil
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	const maxFrameSize = 16384
	total := 0
	remaining := p
	isFirstFrame := true

	for len(remaining) > 0 {
		chunk := remaining
		isLastFrame := true

		if len(chunk) > maxFrameSize {
			chunk = chunk[:maxFrameSize]
			isLastFrame = false
		}

		var opcode byte
		var fin bool

		if isFirstFrame && isLastFrame {
			opcode = 0x02
			fin = true
		} else if isFirstFrame && !isLastFrame {
			opcode = 0x02
			fin = false
		} else if !isFirstFrame && isLastFrame {
			opcode = 0x00
			fin = true
		} else {
			opcode = 0x00
			fin = false
		}

		n, err := writeFrameBytes(c.conn, fin, opcode, chunk)
		if err != nil {
			return total, err
		}
		total += n
		remaining = remaining[len(chunk):]
		isFirstFrame = false
	}

	return total, nil
}

func (c *wsConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.writeMu.Lock()
		_, _ = writeCloseFrame(c.conn, 1000)
		c.writeMu.Unlock()
	})
	return c.conn.Close()
}

func (c *wsConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// Frame functions
func readFrame(r io.Reader) (opcode byte, payload []byte, fin bool, err error) {
	header := make([]byte, 2)
	if _, err = io.ReadFull(r, header); err != nil {
		return 0, nil, false, fmt.Errorf("ws: read frame header: %w", err)
	}

	fin = (header[0] & 0x80) != 0
	opcode = header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	length := uint64(header[1] & 0x7F)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return 0, nil, false, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return 0, nil, false, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, false, err
		}
	}

	if length > 64*1024*1024 {
		return 0, nil, false, fmt.Errorf("ws: frame too large")
	}

	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, nil, false, err
		}
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return opcode, payload, fin, nil
}

func writeFrameBytes(w net.Conn, finFlag bool, opcode byte, payload []byte) (int, error) {
	length := len(payload)

	headerSize := 2 + 4
	if length >= 126 && length < 65536 {
		headerSize += 2
	} else if length >= 65536 {
		headerSize += 8
	}

	frame := make([]byte, 0, headerSize+length)

	firstByte := opcode & 0x0F
	if finFlag {
		firstByte |= 0x80
	}
	frame = append(frame, firstByte)

	switch {
	case length < 126:
		frame = append(frame, 0x80|byte(length))
	case length < 65536:
		frame = append(frame, 0x80|126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(length))
		frame = append(frame, ext...)
	default:
		frame = append(frame, 0x80|127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(length))
		frame = append(frame, ext...)
	}

	var maskKey [4]byte
	if _, err := rand.Read(maskKey[:]); err != nil {
		return 0, err
	}
	frame = append(frame, maskKey[:]...)

	masked := make([]byte, length)
	for i := 0; i < length; i++ {
		masked[i] = payload[i] ^ maskKey[i%4]
	}
	frame = append(frame, masked...)

	_, err := w.Write(frame)
	if err != nil {
		return 0, err
	}

	return length, nil
}

func writeFrame(w net.Conn, opcode byte, payload []byte) (int, error) {
	return writeFrameBytes(w, true, opcode, payload)
}

func writeCloseFrame(w net.Conn, statusCode uint16) (int, error) {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, statusCode)
	return writeFrame(w, 0x08, payload)
}
