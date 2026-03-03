package transport

import (
	"fmt"
	"net"
	"strings"
)

// Transport 定义传输层接口
type Transport interface {
	Wrap(tlsConn net.Conn, cfg *Config) (net.Conn, error)
	Name() string
	ALPNProtos() []string
	Info() TransportInfo
}

// TransportInfo 传输层信息
type TransportInfo struct {
	SupportsMultiplex bool
	SupportsBinary    bool
	RequiresUpgrade   bool
	MaxFrameSize      int
}

// TransportStats 传输层统计
type TransportStats struct {
	ConnectionsOpened int64
	ConnectionsClosed int64
	BytesRead         int64
	BytesWritten      int64
	Errors            int64
}

// Config 传输层配置
type Config struct {
	// 基础配置
	Path        string
	Host        string
	UserAgent   string
	Headers     map[string]string
	MaxIdleTime int
	Target      string // 最终目标地址 (host:port)

	// Xlink 借力配置
	SOCKS5Proxy string // 远程 Worker 使用的 SOCKS5 代理 (格式: user:pass@host:port)
	Fallback    string // 远程 Worker 连接失败时的备用地址 (格式: host:port)

	// 【修复硬伤1】SOCKS5-Out 本地出站代理配置
	SOCKS5OutAddr     string // 本地 SOCKS5 代理地址
	SOCKS5OutUsername string // 本地 SOCKS5 用户名
	SOCKS5OutPassword string // 本地 SOCKS5 密码

	// H2 配置 (保留用于未来 HTTP/2 支持)
	H2Config interface{}
}

// Validate 验证配置
func (c *Config) Validate() error {
	if c.Path != "" && c.Path[0] != '/' {
		return fmt.Errorf("transport: path must start with '/', got %q", c.Path)
	}
	if c.Target != "" {
		if !strings.Contains(c.Target, ":") {
			return fmt.Errorf("transport: target must be host:port, got %q", c.Target)
		}
	}
	return nil
}

// Clone 克隆配置
func (c *Config) Clone() *Config {
	clone := *c
	if c.Headers != nil {
		clone.Headers = make(map[string]string, len(c.Headers))
		for k, v := range c.Headers {
			clone.Headers[k] = v
		}
	}
	return &clone
}

// Normalize 规范化配置
func (c *Config) Normalize() {
	if c.Path == "" {
		c.Path = "/"
	}
}

// IsProxyMode 检查是否为代理模式
func (c *Config) IsProxyMode() bool {
	return c.Target != "" || c.Path == "" || c.Path == "/"
}

// HasRemoteProxy 检查是否配置了远程代理
func (c *Config) HasRemoteProxy() bool {
	return c.SOCKS5Proxy != "" || c.Fallback != ""
}

// HasSOCKS5Out 检查是否配置了本地 SOCKS5 出站
func (c *Config) HasSOCKS5Out() bool {
	return c.SOCKS5OutAddr != ""
}

// Get 根据名称获取传输层
// 【修复硬伤1】添加 socks5-out 支持
func Get(name string) Transport {
	switch strings.ToLower(name) {
	case "ws", "websocket":
		return &WSTransport{}
	case "h2", "http2", "h2c":
		return &H2Transport{}
	case "socks5-out", "socks5out": // 【新增】支持 socks5-out
		return &SOCKS5OutTransport{}
	case "raw", "direct", "tcp", "":
		return &RawTransport{}
	default:
		return &RawTransport{}
	}
}

// GetWithConfig 根据名称和配置获取传输层
// 【修复硬伤1】专门处理需要配置的传输层
func GetWithConfig(name string, socks5Addr, username, password string) Transport {
	switch strings.ToLower(name) {
	case "socks5-out", "socks5out":
		return &SOCKS5OutTransport{
			ProxyAddr: socks5Addr,
			Username:  username,
			Password:  password,
		}
	default:
		return Get(name)
	}
}

// Names 返回所有支持的传输层名称
func Names() []string {
	return []string{"raw", "ws", "h2", "socks5-out"}
}

// IsValidTransport 检查传输层名称是否有效
func IsValidTransport(name string) bool {
	validTransports := map[string]bool{
		"raw": true, "ws": true, "h2": true,
		"websocket": true, "http2": true, "h2c": true,
		"direct": true, "tcp": true,
		"socks5-out": true, "socks5out": true,
	}
	return validTransports[strings.ToLower(name)]
}
