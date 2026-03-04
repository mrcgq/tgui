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

// Config 传输层配置
type Config struct {
	Path        string
	Host        string
	UserAgent   string
	Headers     map[string]string
	MaxIdleTime int
	Target      string

	// Xlink 借力配置
	SOCKS5Proxy string
	Fallback    string

	// SOCKS5 出站配置
	SOCKS5Addr     string
	SOCKS5Username string
	SOCKS5Password string
}

// Validate 验证配置
func (c *Config) Validate() error {
	if c.Path != "" && c.Path[0] != '/' {
		return fmt.Errorf("transport: path must start with '/', got %q", c.Path)
	}
	return nil
}

// Clone 克隆配置
func (c *Config) Clone() *Config {
	if c == nil {
		return &Config{}
	}
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

// HasRemoteProxy 检查是否配置了远程代理
func (c *Config) HasRemoteProxy() bool {
	return c.SOCKS5Proxy != "" || c.Fallback != ""
}

// Get 根据名称获取传输层
func Get(name string) Transport {
	switch strings.ToLower(name) {
	case "ws", "websocket":
		return &WSTransport{}
	case "h2", "http2", "h2c":
		return &H2Transport{}
	case "socks5-out", "socks5out":
		return &SOCKS5OutTransport{}
	case "raw", "direct", "tcp", "":
		return &RawTransport{}
	default:
		return &RawTransport{}
	}
}

// GetWithConfig 根据名称获取传输层并附加配置
func GetWithConfig(name string, cfg *Config) Transport {
	t := Get(name)
	if name == "socks5-out" || name == "socks5out" {
		if cfg != nil {
			return &SOCKS5OutTransport{
				ProxyAddr: cfg.SOCKS5Addr,
				Username:  cfg.SOCKS5Username,
				Password:  cfg.SOCKS5Password,
			}
		}
	}
	return t
}

// Names 返回所有支持的传输层名称
func Names() []string {
	return []string{"raw", "ws", "h2", "socks5-out"}
}
