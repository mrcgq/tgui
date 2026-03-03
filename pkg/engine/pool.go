package engine

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/user/tls-client/pkg/fingerprint"
	"github.com/user/tls-client/pkg/verify"
)

// PoolConfig configures the connection pool.
// 【修复遗漏1】这个结构体现在可以从配置文件完全读取
type PoolConfig struct {
	MaxIdle     int
	MaxPerKey   int
	IdleTimeout time.Duration
	MaxLifetime time.Duration
}

// DefaultPoolConfig returns sensible defaults for the connection pool.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxIdle:     10,
		MaxPerKey:   3,
		IdleTimeout: 120 * time.Second,
		MaxLifetime: 10 * time.Minute,
	}
}

// ConnPool manages reusable TLS connections with health checking.
type ConnPool struct {
	mu     sync.Mutex
	conns  map[string][]*poolEntry
	cfg    PoolConfig
	closed bool

	expiredCount int64
}

type poolEntry struct {
	conn      net.Conn
	createdAt time.Time
	lastUsed  time.Time
	inUse     bool
}

// PoolStats holds pool statistics.
type PoolStats struct {
	Total   int
	Idle    int
	InUse   int
	Expired int64
	Keys    int
}

// NewConnPool creates a connection pool with the given config.
func NewConnPool(maxIdle int, idleTimeout time.Duration) *ConnPool {
	cfg := DefaultPoolConfig()
	if maxIdle > 0 {
		cfg.MaxIdle = maxIdle
	}
	if idleTimeout > 0 {
		cfg.IdleTimeout = idleTimeout
	}
	return NewConnPoolWithConfig(cfg)
}

// NewConnPoolWithConfig creates a connection pool with full configuration.
// 【修复遗漏1】这个函数现在被 tunnel.go 使用来读取配置文件中的 pool 参数
func NewConnPoolWithConfig(cfg PoolConfig) *ConnPool {
	// 应用默认值
	if cfg.MaxIdle <= 0 {
		cfg.MaxIdle = 10
	}
	if cfg.MaxPerKey <= 0 {
		cfg.MaxPerKey = 3
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 120 * time.Second
	}
	if cfg.MaxLifetime <= 0 {
		cfg.MaxLifetime = 10 * time.Minute
	}

	p := &ConnPool{
		conns: make(map[string][]*poolEntry),
		cfg:   cfg,
	}
	go p.cleanup()
	return p
}

// Get retrieves or creates a TLS connection.
func (p *ConnPool) Get(ctx context.Context, key string, cfg *DialConfig) (net.Conn, error) {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()
		return p.dial(ctx, cfg)
	}

	entries := p.conns[key]
	now := time.Now()

	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if entry.inUse {
			continue
		}

		if now.Sub(entry.lastUsed) > p.cfg.IdleTimeout ||
			now.Sub(entry.createdAt) > p.cfg.MaxLifetime {
			entry.conn.Close()
			entries = append(entries[:i], entries[i+1:]...)
			atomic.AddInt64(&p.expiredCount, 1)
			continue
		}

		if !p.probeConnection(entry.conn) {
			entry.conn.Close()
			entries = append(entries[:i], entries[i+1:]...)
			continue
		}

		entry.inUse = true
		entry.lastUsed = now
		p.conns[key] = entries
		p.mu.Unlock()

		return &pooledConn{
			Conn:  entry.conn,
			pool:  p,
			key:   key,
			entry: entry,
		}, nil
	}

	p.conns[key] = entries
	p.mu.Unlock()

	return p.dial(ctx, cfg)
}

func (p *ConnPool) probeConnection(conn net.Conn) bool {
	probe := make([]byte, 1)

	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond)); err != nil {
		return false
	}

	n, err := conn.Read(probe)

	_ = conn.SetReadDeadline(time.Time{})

	if n > 0 {
		return false
	}

	if err == nil {
		return true
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	return false
}

func (p *ConnPool) dial(ctx context.Context, cfg *DialConfig) (net.Conn, error) {
	result, err := Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return result.Conn, nil
}

// Put returns a connection to the pool for reuse.
func (p *ConnPool) Put(key string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		conn.Close()
		return
	}

	entries := p.conns[key]
	idleCount := 0
	for _, e := range entries {
		if !e.inUse {
			idleCount++
		}
	}

	if idleCount >= p.cfg.MaxPerKey || len(entries) >= p.cfg.MaxIdle {
		conn.Close()
		return
	}

	p.conns[key] = append(entries, &poolEntry{
		conn:      conn,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		inUse:     false,
	})
}

// Release marks a pooled connection as available.
func (p *ConnPool) Release(key string, entry *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		entry.conn.Close()
		return
	}
	entry.inUse = false
	entry.lastUsed = time.Now()
}

// Remove removes a connection from the pool (e.g., on error).
func (p *ConnPool) Remove(key string, entry *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entries := p.conns[key]
	for i, e := range entries {
		if e == entry {
			e.conn.Close()
			p.conns[key] = append(entries[:i], entries[i+1:]...)
			return
		}
	}
}

func (p *ConnPool) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}

		now := time.Now()
		for key, entries := range p.conns {
			var active []*poolEntry
			for _, entry := range entries {
				if entry.inUse {
					active = append(active, entry)
					continue
				}
				if now.Sub(entry.lastUsed) > p.cfg.IdleTimeout ||
					now.Sub(entry.createdAt) > p.cfg.MaxLifetime {
					entry.conn.Close()
					atomic.AddInt64(&p.expiredCount, 1)
					continue
				}
				active = append(active, entry)
			}
			if len(active) > 0 {
				p.conns[key] = active
			} else {
				delete(p.conns, key)
			}
		}
		p.mu.Unlock()
	}
}

// Close closes all pooled connections.
func (p *ConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, entries := range p.conns {
		for _, entry := range entries {
			entry.conn.Close()
		}
	}
	p.conns = make(map[string][]*poolEntry)
}

// Stats returns comprehensive pool statistics.
func (p *ConnPool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	var stats PoolStats
	stats.Keys = len(p.conns)
	stats.Expired = atomic.LoadInt64(&p.expiredCount)
	for _, entries := range p.conns {
		for _, entry := range entries {
			stats.Total++
			if entry.inUse {
				stats.InUse++
			} else {
				stats.Idle++
			}
		}
	}
	return stats
}

// Config returns the pool configuration
func (p *ConnPool) Config() PoolConfig {
	return p.cfg
}

type pooledConn struct {
	net.Conn
	pool     *ConnPool
	key      string
	entry    *poolEntry
	released atomic.Bool
}

func (c *pooledConn) Close() error {
	if !c.released.CompareAndSwap(false, true) {
		return nil
	}
	c.pool.Release(c.key, c.entry)
	return nil
}

// CloseWithError closes the connection and removes it from pool.
func (c *pooledConn) CloseWithError() error {
	if !c.released.CompareAndSwap(false, true) {
		return nil
	}
	c.pool.Remove(c.key, c.entry)
	return nil
}

// DialForProxy dials a TLS connection for the proxy outbound path.
func DialForProxy(ctx context.Context, address, sni string, profile *fingerprint.BrowserProfile, verifyMode verify.Mode) (net.Conn, string, error) {
	result, err := Dial(ctx, &DialConfig{
		Address:    address,
		SNI:        sni,
		Profile:    profile,
		VerifyMode: verifyMode,
		ALPN:       []string{"http/1.1"},
	})
	if err != nil {
		return nil, "", err
	}
	return result.Conn, result.NegProto, nil
}
