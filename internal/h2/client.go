package h2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	ErrClientClosed = errors.New("h2: client closed")
	ErrNotReady     = errors.New("h2: settings exchange not completed")
)

type Client struct {
	conn   net.Conn
	framer *http2.Framer
	fp     *FingerprintConfig

	hpackBuf bytes.Buffer
	hpackEnc *hpack.Encoder

	nextStreamID uint32
	mu           sync.Mutex
	streams      map[uint32]*stream

	writeMu sync.Mutex

	state        int32
	closeOnce    sync.Once
	closeCh      chan struct{}

	connSendWindow int64
	serverInitWin  uint32

	responseTimeout time.Duration

	settingsReady chan struct{}
	settingsOnce  sync.Once
}

type stream struct {
	id         uint32
	headers    chan *headerResult
	data       chan *dataChunk
	done       chan struct{}
	sendWindow int64
	doneOnce   sync.Once
	closed     atomic.Bool
}

type headerResult struct {
	status  int
	headers http.Header
	err     error
}

type dataChunk struct {
	data      []byte
	endStream bool
}

func (s *stream) closeDone() {
	s.doneOnce.Do(func() {
		s.closed.Store(true)
		close(s.done)
	})
}

func NewClient(conn net.Conn, fp *FingerprintConfig) (*Client, error) {
	c := &Client{
		conn:            conn,
		fp:              fp,
		nextStreamID:    1,
		streams:         make(map[uint32]*stream),
		closeCh:         make(chan struct{}),
		connSendWindow:  65535,
		serverInitWin:   65535,
		responseTimeout: 30 * time.Second,
		settingsReady:   make(chan struct{}),
	}

	preface := BuildPreface(fp)
	if _, err := conn.Write(preface); err != nil {
		return nil, fmt.Errorf("h2: write preface: %w", err)
	}

	c.framer = http2.NewFramer(conn, conn)
	c.framer.SetMaxReadFrameSize(1 << 24)
	c.framer.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	c.framer.MaxHeaderListSize = 262144

	c.hpackEnc = hpack.NewEncoder(&c.hpackBuf)

	go c.readLoop()

	return c, nil
}

func (c *Client) WaitReady(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	select {
	case <-c.settingsReady:
		return nil
	case <-c.closeCh:
		return ErrClientClosed
	case <-time.After(timeout):
		return fmt.Errorf("h2: settings exchange timeout")
	}
}

func (c *Client) SetResponseTimeout(d time.Duration) {
	c.responseTimeout = d
}

func (c *Client) readLoop() {
	defer c.closeInternal(nil)

	for {
		f, err := c.framer.ReadFrame()
		if err != nil {
			if atomic.LoadInt32(&c.state) == 2 {
				return
			}
			c.closeInternal(err)
			return
		}

		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				c.handleServerSettings(f)
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				c.writeMu.Lock()
				_ = c.framer.WritePing(true, f.Data)
				c.writeMu.Unlock()
			}
		case *http2.WindowUpdateFrame:
			c.handleWindowUpdate(f)
		case *http2.GoAwayFrame:
			atomic.StoreInt32(&c.state, 1)
			c.closeInternal(nil)
			return
		case *http2.MetaHeadersFrame:
			c.handleResponseHeaders(f)
		case *http2.DataFrame:
			c.handleResponseData(f)
		case *http2.RSTStreamFrame:
			c.handleRSTStream(f)
		}
	}
}

func (c *Client) handleServerSettings(f *http2.SettingsFrame) {
	var newInitWin uint32
	hasNewInitWin := false

	_ = f.ForeachSetting(func(s http2.Setting) error {
		if s.ID == http2.SettingInitialWindowSize {
			newInitWin = s.Val
			hasNewInitWin = true
		}
		return nil
	})

	if hasNewInitWin {
		c.mu.Lock()
		oldInitWin := c.serverInitWin
		c.serverInitWin = newInitWin
		delta := int64(newInitWin) - int64(oldInitWin)
		for _, s := range c.streams {
			atomic.AddInt64(&s.sendWindow, delta)
		}
		c.mu.Unlock()
	}

	c.writeMu.Lock()
	_ = c.framer.WriteSettingsAck()
	c.writeMu.Unlock()

	c.settingsOnce.Do(func() {
		close(c.settingsReady)
	})
}

func (c *Client) handleWindowUpdate(f *http2.WindowUpdateFrame) {
	if f.StreamID == 0 {
		atomic.AddInt64(&c.connSendWindow, int64(f.Increment))
		return
	}
	c.mu.Lock()
	s, ok := c.streams[f.StreamID]
	c.mu.Unlock()
	if ok {
		atomic.AddInt64(&s.sendWindow, int64(f.Increment))
	}
}

func (c *Client) handleResponseHeaders(f *http2.MetaHeadersFrame) {
	c.mu.Lock()
	s, ok := c.streams[f.StreamID]
	c.mu.Unlock()
	if !ok {
		return
	}

	hdr := make(http.Header)
	status := 200
	for _, field := range f.Fields {
		if field.Name == ":status" {
			status, _ = strconv.Atoi(field.Value)
		} else {
			hdr.Add(field.Name, field.Value)
		}
	}

	select {
	case s.headers <- &headerResult{status: status, headers: hdr}:
	default:
	}

	if f.StreamEnded() {
		s.closeDone()
	}
}

func (c *Client) handleResponseData(f *http2.DataFrame) {
	c.mu.Lock()
	s, ok := c.streams[f.StreamID]
	c.mu.Unlock()
	if !ok || s.closed.Load() {
		return
	}

	data := make([]byte, len(f.Data()))
	copy(data, f.Data())

	n := uint32(len(data))
	if n > 0 {
		c.writeMu.Lock()
		_ = c.framer.WriteWindowUpdate(0, n)
		_ = c.framer.WriteWindowUpdate(f.StreamID, n)
		c.writeMu.Unlock()
	}

	select {
	case s.data <- &dataChunk{data: data, endStream: f.StreamEnded()}:
	default:
	}

	if f.StreamEnded() {
		s.closeDone()
	}
}

func (c *Client) handleRSTStream(f *http2.RSTStreamFrame) {
	c.mu.Lock()
	s, ok := c.streams[f.StreamID]
	c.mu.Unlock()
	if !ok {
		return
	}
	select {
	case s.headers <- &headerResult{err: fmt.Errorf("h2: stream reset")}:
	default:
	}
	s.closeDone()
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if atomic.LoadInt32(&c.state) != 0 {
		return nil, ErrClientClosed
	}

	c.mu.Lock()
	streamID := c.nextStreamID
	c.nextStreamID += 2
	s := &stream{
		id:         streamID,
		headers:    make(chan *headerResult, 1),
		data:       make(chan *dataChunk, 64),
		done:       make(chan struct{}),
		sendWindow: int64(c.serverInitWin),
	}
	c.streams[streamID] = s
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.streams, streamID)
		c.mu.Unlock()
	}()

	headerBlock, err := c.encodeHeaders(req)
	if err != nil {
		return nil, err
	}

	hasBody := req.Body != nil && req.Body != http.NoBody

	c.writeMu.Lock()
	err = c.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headerBlock,
		EndStream:     !hasBody,
		EndHeaders:    true,
	})
	c.writeMu.Unlock()
	if err != nil {
		return nil, err
	}

	if hasBody {
		if err := c.sendBody(streamID, req.Body); err != nil {
			return nil, err
		}
	}

	select {
	case hr := <-s.headers:
		if hr.err != nil {
			return nil, hr.err
		}
		resp := &http.Response{
			StatusCode:    hr.status,
			Status:        fmt.Sprintf("%d %s", hr.status, http.StatusText(hr.status)),
			Header:        hr.headers,
			Proto:         "HTTP/2.0",
			ProtoMajor:    2,
			ProtoMinor:    0,
			Request:       req,
			Body:          &streamBody{stream: s, closeCh: c.closeCh},
			ContentLength: -1,
		}
		if cl := hr.headers.Get("Content-Length"); cl != "" {
			resp.ContentLength, _ = strconv.ParseInt(cl, 10, 64)
		}
		return resp, nil
	case <-c.closeCh:
		return nil, ErrClientClosed
	case <-time.After(c.responseTimeout):
		return nil, fmt.Errorf("h2: response timeout")
	}
}

func (c *Client) encodeHeaders(req *http.Request) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.hpackBuf.Reset()

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}

	pseudoValues := map[string]string{
		":method":    req.Method,
		":authority": host,
		":scheme":    "https",
		":path":      path,
	}

	for _, key := range c.fp.PseudoHeaderOrder {
		if val, ok := pseudoValues[key]; ok {
			_ = c.hpackEnc.WriteField(hpack.HeaderField{Name: key, Value: val})
		}
	}

	skipHeaders := map[string]bool{
		"host": true, "transfer-encoding": true, "connection": true,
	}
	for key, vals := range req.Header {
		lk := strings.ToLower(key)
		if skipHeaders[lk] || strings.HasPrefix(lk, ":") {
			continue
		}
		for _, v := range vals {
			_ = c.hpackEnc.WriteField(hpack.HeaderField{Name: lk, Value: v})
		}
	}

	out := make([]byte, c.hpackBuf.Len())
	copy(out, c.hpackBuf.Bytes())
	return out, nil
}

func (c *Client) sendBody(streamID uint32, body io.Reader) error {
	buf := make([]byte, c.fp.GetMaxFrameSize())
	for {
		n, err := body.Read(buf)
		if n > 0 {
			endStream := err == io.EOF
			c.writeMu.Lock()
			writeErr := c.framer.WriteData(streamID, endStream, buf[:n])
			c.writeMu.Unlock()
			if writeErr != nil {
				return writeErr
			}
			if endStream {
				return nil
			}
		}
		if err != nil {
			if err == io.EOF {
				c.writeMu.Lock()
				writeErr := c.framer.WriteData(streamID, true, nil)
				c.writeMu.Unlock()
				return writeErr
			}
			return err
		}
	}
}

func (c *Client) closeInternal(err error) {
	c.closeOnce.Do(func() {
		atomic.StoreInt32(&c.state, 2)
		close(c.closeCh)
		c.settingsOnce.Do(func() { close(c.settingsReady) })
		c.mu.Lock()
		for _, s := range c.streams {
			select {
			case s.headers <- &headerResult{err: ErrClientClosed}:
			default:
			}
			s.closeDone()
		}
		c.mu.Unlock()
		c.conn.Close()
	})
}

func (c *Client) Close() error {
	c.closeInternal(nil)
	return nil
}

func (c *Client) IsClosed() bool {
	return atomic.LoadInt32(&c.state) == 2
}

type streamBody struct {
	stream  *stream
	closeCh chan struct{}
	buf     []byte
	eof     bool
}

func (b *streamBody) Read(p []byte) (int, error) {
	if len(b.buf) > 0 {
		n := copy(p, b.buf)
		b.buf = b.buf[n:]
		return n, nil
	}
	if b.eof {
		return 0, io.EOF
	}
	select {
	case chunk, ok := <-b.stream.data:
		if !ok {
			return 0, io.EOF
		}
		if chunk.endStream {
			b.eof = true
		}
		n := copy(p, chunk.data)
		if n < len(chunk.data) {
			b.buf = chunk.data[n:]
		}
		if b.eof && len(b.buf) == 0 {
			return n, io.EOF
		}
		return n, nil
	case <-b.stream.done:
		return 0, io.EOF
	case <-b.closeCh:
		return 0, ErrClientClosed
	}
}

func (b *streamBody) Close() error {
	return nil
}
