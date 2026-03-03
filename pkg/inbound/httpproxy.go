package inbound

import (
	"bufio"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// HTTPProxyServer implements an HTTP CONNECT proxy.
type HTTPProxyServer struct {
	Addr      string
	Logger    *zap.Logger
	OnConnect TunnelFunc
	listener  net.Listener
	wg        sync.WaitGroup
	closeCh   chan struct{}

	activeConns int64
	totalConns  int64
}

func NewHTTPProxyServer(addr string, logger *zap.Logger, onConnect TunnelFunc) *HTTPProxyServer {
	return &HTTPProxyServer{
		Addr:      addr,
		Logger:    logger,
		OnConnect: onConnect,
		closeCh:   make(chan struct{}),
	}
}

func (s *HTTPProxyServer) Start() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.Logger.Info("http proxy server started", zap.String("addr", s.Addr))

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-s.closeCh:
					return
				default:
					continue
				}
			}
			atomic.AddInt64(&s.totalConns, 1)
			atomic.AddInt64(&s.activeConns, 1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer atomic.AddInt64(&s.activeConns, -1)
				s.handleConn(conn)
			}()
		}
	}()
	return nil
}

func (s *HTTPProxyServer) Stop() {
	close(s.closeCh)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
}

func (s *HTTPProxyServer) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReaderSize(conn, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method != http.MethodConnect {
		_, _ = conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}

	target := req.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}

	domain := req.URL.Hostname()
	s.Logger.Debug("http connect", zap.String("target", target))

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	_ = conn.SetDeadline(time.Time{})

	if s.OnConnect != nil {
		s.OnConnect(conn, target, domain)
	}
}
