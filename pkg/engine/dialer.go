package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"time"

	"github.com/user/tls-client/pkg/fingerprint"
	"github.com/user/tls-client/pkg/verify"

	utls "github.com/refraction-networking/utls"
)

// DialConfig holds parameters for a single TLS dial operation.
type DialConfig struct {
	Address    string
	SNI        string
	Profile    *fingerprint.BrowserProfile
	VerifyMode verify.Mode
	VerifyOpts *verify.Options
	Timeout    time.Duration
	ALPN       []string
	Retry      *RetryConfig
}

// RetryConfig controls retry behavior for failed dial attempts.
// 【修复硬伤3】Jitter 字段现在可以从配置文件读取
type RetryConfig struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Jitter      float64 // 【修复硬伤3】抖动系数，0.0-1.0，从配置文件读取
}

// DialResult holds the result of a TLS dial operation.
type DialResult struct {
	Conn     net.Conn
	TLSConn  *utls.UConn
	NegProto string
	Latency  time.Duration
	Attempts int
}

// DialMetrics tracks dial operation statistics.
type DialMetrics struct {
	SuccessCount int64
	FailureCount int64
	TotalLatency int64
}

var globalDialMetrics DialMetrics

// GetDialMetrics returns a snapshot of global dial metrics.
func GetDialMetrics() DialMetrics {
	return DialMetrics{
		SuccessCount: atomic.LoadInt64(&globalDialMetrics.SuccessCount),
		FailureCount: atomic.LoadInt64(&globalDialMetrics.FailureCount),
		TotalLatency: atomic.LoadInt64(&globalDialMetrics.TotalLatency),
	}
}

// ResetDialMetrics resets dial metrics (useful for testing)
func ResetDialMetrics() {
	atomic.StoreInt64(&globalDialMetrics.SuccessCount, 0)
	atomic.StoreInt64(&globalDialMetrics.FailureCount, 0)
	atomic.StoreInt64(&globalDialMetrics.TotalLatency, 0)
}

// Dial establishes a TLS connection with the specified fingerprint.
func Dial(ctx context.Context, cfg *DialConfig) (*DialResult, error) {
	if cfg.Profile == nil {
		cfg.Profile = fingerprint.MustGet(fingerprint.DefaultProfile())
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if len(cfg.ALPN) == 0 {
		cfg.ALPN = []string{"h2", "http/1.1"}
	}

	maxAttempts := 1
	var baseDelay, maxDelay time.Duration
	jitter := 0.2 // 默认抖动系数

	if cfg.Retry != nil {
		if cfg.Retry.MaxAttempts > 1 {
			maxAttempts = cfg.Retry.MaxAttempts
		}
		baseDelay = cfg.Retry.BaseDelay
		if baseDelay == 0 {
			baseDelay = 500 * time.Millisecond
		}
		maxDelay = cfg.Retry.MaxDelay
		if maxDelay == 0 {
			maxDelay = 10 * time.Second
		}
		// 【修复硬伤3】使用配置的 Jitter 值
		if cfg.Retry.Jitter > 0 {
			jitter = cfg.Retry.Jitter
		}
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			delay := baseDelay * time.Duration(1<<uint(attempt-2))
			if delay > maxDelay {
				delay = maxDelay
			}
			// 【修复硬伤3】使用可配置的 Jitter
			jitterDelta := time.Duration(float64(delay) * jitter * (2*rand.Float64() - 1))
			delay += jitterDelta
			if delay < 0 {
				delay = 0
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		result, err := dialOnce(ctx, cfg)
		if err == nil {
			result.Attempts = attempt
			atomic.AddInt64(&globalDialMetrics.SuccessCount, 1)
			atomic.AddInt64(&globalDialMetrics.TotalLatency, int64(result.Latency))
			return result, nil
		}

		lastErr = err
		atomic.AddInt64(&globalDialMetrics.FailureCount, 1)

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("engine: dial failed after %d attempts: %w", maxAttempts, lastErr)
}

func dialOnce(ctx context.Context, cfg *DialConfig) (*DialResult, error) {
	start := time.Now()

	// TCP connect
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("engine: tcp dial %s: %w", cfg.Address, err)
	}

	// Build TLS config
	tlsCfg := &tls.Config{
		NextProtos: cfg.ALPN,
	}
	verify.ApplyToTLSConfig(tlsCfg, cfg.VerifyMode, cfg.SNI, cfg.VerifyOpts)

	// utls connection with fingerprint
	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName:            cfg.SNI,
		NextProtos:            cfg.ALPN,
		InsecureSkipVerify:    tlsCfg.InsecureSkipVerify,
		VerifyPeerCertificate: tlsCfg.VerifyPeerCertificate,
		RootCAs:               tlsCfg.RootCAs,
	}, cfg.Profile.ClientHelloID)

	// ========================================================================
	// [CRITICAL FIX] Force ALPN lock (universal fix for all platforms)
	// ========================================================================
	if err := tlsConn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("engine: build handshake state: %w", err)
	}

	// Override ALPN extension in the fingerprint with transport-required protocols
	for _, ext := range tlsConn.Extensions {
		if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
			alpnExt.AlpnProtocols = cfg.ALPN
			break
		}
	}

	// Re-serialize ClientHello so the ALPN change takes effect
	if err := tlsConn.MarshalClientHello(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("engine: marshal client hello: %w", err)
	}
	// ========================================================================

	// Handshake with timeout
	handshakeCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("engine: tls handshake to %s (sni=%s): %w",
			cfg.Address, cfg.SNI, err)
	}

	negProto := tlsConn.ConnectionState().NegotiatedProtocol

	return &DialResult{
		Conn:     tlsConn,
		TLSConn:  tlsConn,
		NegProto: negProto,
		Latency:  time.Since(start),
	}, nil
}

// DialWithRetry is a convenience function for dialing with custom retry settings
func DialWithRetry(ctx context.Context, address, sni string, profile *fingerprint.BrowserProfile,
	verifyMode verify.Mode, maxAttempts int, jitter float64) (*DialResult, error) {
	return Dial(ctx, &DialConfig{
		Address:    address,
		SNI:        sni,
		Profile:    profile,
		VerifyMode: verifyMode,
		Retry: &RetryConfig{
			MaxAttempts: maxAttempts,
			BaseDelay:   500 * time.Millisecond,
			MaxDelay:    10 * time.Second,
			Jitter:      jitter,
		},
	})
}
