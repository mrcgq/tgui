package inbound

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	socks5Version      = 0x05
	socks5AuthNone     = 0x00
	socks5AuthUserPass = 0x02
	socks5AuthNoAccept = 0xFF
	socks5CmdConnect   = 0x01
	socks5AtypIPv4     = 0x01
	socks5AtypDomain   = 0x03
	socks5AtypIPv6     = 0x04
	socks5RepSuccess   = 0x00
	socks5RepFail      = 0x01
	socks5RepCmdNotSup = 0x07
)

// TunnelFunc is called when a CONNECT request is accepted.
type TunnelFunc func(clientConn net.Conn, target, domain string)

// SOCKS5Server implements a SOCKS5 proxy (RFC 1928).
type SOCKS5Server struct {
	Addr      string
	Logger    *zap.Logger
	OnConnect TunnelFunc
	listener  net.Listener
	wg        sync.WaitGroup
	closeCh   chan struct{}

	activeConns int64
	totalConns  int64
}

// NewSOCKS5Server 创建 SOCKS5 服务器
func NewSOCKS5Server(addr string, logger *zap.Logger, onConnect TunnelFunc) *SOCKS5Server {
	return &SOCKS5Server{
		Addr:      addr,
		Logger:    logger,
		OnConnect: onConnect,
		closeCh:   make(chan struct{}),
	}
}

// Start 启动服务器
func (s *SOCKS5Server) Start() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("socks5: listen %s: %w", s.Addr, err)
	}
	s.listener = ln
	s.Logger.Info("socks5 server started", zap.String("addr", s.Addr))

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
					s.Logger.Warn("socks5: accept error", zap.Error(err))
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

// Stop 停止服务器
func (s *SOCKS5Server) Stop() {
	close(s.closeCh)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	s.Logger.Info("socks5 server stopped",
		zap.Int64("total_connections", atomic.LoadInt64(&s.totalConns)))
}

func (s *SOCKS5Server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socks5Version {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	_, _ = conn.Write([]byte{socks5Version, socks5AuthNone})

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != socks5Version {
		s.sendReply(conn, socks5RepFail)
		return
	}
	cmd := req[1]
	atyp := req[3]

	target, domain, err := s.readAddress(conn, atyp)
	if err != nil {
		s.sendReply(conn, socks5RepFail)
		return
	}

	if cmd != socks5CmdConnect {
		s.sendReply(conn, socks5RepCmdNotSup)
		return
	}

	s.Logger.Debug("socks5 connect",
		zap.String("target", target),
		zap.String("domain", domain))

	s.sendReply(conn, socks5RepSuccess)
	_ = conn.SetDeadline(time.Time{})

	if s.OnConnect != nil {
		s.OnConnect(conn, target, domain)
	}
}

func (s *SOCKS5Server) readAddress(conn net.Conn, atyp byte) (target, domain string, err error) {
	var host string
	switch atyp {
	case socks5AtypIPv4:
		addr := make([]byte, 4)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err = io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)
		domain = host
	case socks5AtypIPv6:
		addr := make([]byte, 16)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		err = fmt.Errorf("socks5: unsupported atyp 0x%02x", atyp)
		return
	}
	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target = net.JoinHostPort(host, fmt.Sprintf("%d", port))
	return
}

func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte) {
	reply := []byte{socks5Version, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	_, _ = conn.Write(reply)
}
