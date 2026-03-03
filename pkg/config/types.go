package config

import "time"

// Config 是主配置结构 - 完全体版本
type Config struct {
	Global         GlobalConfig         `yaml:"global"`
	Inbound        InboundConfig        `yaml:"inbound"`
	Fingerprint    FingerprintConfig    `yaml:"fingerprint"`
	TLS            TLSConfig            `yaml:"tls"`
	Nodes          []NodeConfig         `yaml:"nodes"`
	ClientBehavior ClientBehaviorConfig `yaml:"client_behavior"` // 【修复硬伤2】新增客户端行为配置
	API            APIConfig            `yaml:"api"`             // 【修复遗漏2】新增API配置
	Health         HealthConfig         `yaml:"health"`          // 【修复遗漏2】新增健康检查配置
	ProxyIPs       ProxyIPPoolConfig    `yaml:"proxy_ips"`       // 【修复遗漏3】新增ProxyIP池配置
}

// GlobalConfig 全局配置
type GlobalConfig struct {
	LogLevel  string        `yaml:"log_level"`
	LogOutput string        `yaml:"log_output"`
	Metrics   MetricsConfig `yaml:"metrics"`
}

// MetricsConfig 指标配置
type MetricsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

// InboundConfig 入站配置
type InboundConfig struct {
	SOCKS5 ListenConfig `yaml:"socks5"`
	HTTP   ListenConfig `yaml:"http"`
}

// ListenConfig 监听配置
type ListenConfig struct {
	Listen   string `yaml:"listen"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// FingerprintConfig 指纹配置
type FingerprintConfig struct {
	Rotation RotationConfig `yaml:"rotation"`
}

// RotationConfig 轮换配置
type RotationConfig struct {
	Mode     string   `yaml:"mode"`
	Profile  string   `yaml:"profile"`
	Profiles []string `yaml:"profiles"`
	Interval string   `yaml:"interval"`
	Weights  []int    `yaml:"weights"`
}

// TLSConfig TLS 配置
type TLSConfig struct {
	VerifyMode string     `yaml:"verify_mode"`
	VerifyOpts VerifyOpts `yaml:"verify_opts"`
}

// VerifyOpts 验证选项
type VerifyOpts struct {
	CertPin  string `yaml:"cert_pin"`
	CustomCA string `yaml:"custom_ca"`
}

// NodeConfig 节点配置
type NodeConfig struct {
	Name          string        `yaml:"name"`
	Address       string        `yaml:"address"`
	SNI           string        `yaml:"sni"`
	Fingerprint   string        `yaml:"fingerprint"`
	Active        bool          `yaml:"active"`
	Transport     string        `yaml:"transport"`
	TransportOpts TransportOpts `yaml:"transport_opts"`
	Fallback      []string      `yaml:"transport_fallback"`
	Retry         RetryOpts     `yaml:"retry"`
	Pool          PoolOpts      `yaml:"pool"`

	// 远程代理配置 (Xlink 借力机制)
	RemoteProxy RemoteProxyConfig `yaml:"remote_proxy"`
}

// TransportOpts 传输选项
type TransportOpts struct {
	WSPath         string            `yaml:"ws_path"`
	WSHost         string            `yaml:"ws_host"`
	WSHeaders      map[string]string `yaml:"ws_headers"`
	H2Path         string            `yaml:"h2_path"`
	SOCKS5Addr     string            `yaml:"socks5_addr"`
	SOCKS5Username string            `yaml:"socks5_username"`
	SOCKS5Password string            `yaml:"socks5_password"`
}

// RetryOpts 重试选项 - 【修复硬伤3】添加 Jitter 字段
type RetryOpts struct {
	MaxAttempts int     `yaml:"max_attempts"`
	BaseDelay   string  `yaml:"base_delay"`
	MaxDelay    string  `yaml:"max_delay"`
	Jitter      float64 `yaml:"jitter"` // 【新增】抖动系数 0.0-1.0
}

// PoolOpts 连接池选项
type PoolOpts struct {
	MaxIdle     int    `yaml:"max_idle"`
	MaxPerKey   int    `yaml:"max_per_key"`
	IdleTimeout string `yaml:"idle_timeout"`
	MaxLifetime string `yaml:"max_lifetime"`
}

// RemoteProxyConfig 远程代理配置 (Xlink 借力机制)
type RemoteProxyConfig struct {
	// SOCKS5 代理地址，Worker 会通过此代理连接目标
	// 格式: user:pass@host:port 或 host:port
	SOCKS5 string `yaml:"socks5"`

	// Fallback 地址，当直连失败时 Worker 会使用此地址
	// 格式: host:port
	Fallback string `yaml:"fallback"`
}

// HasRemoteProxy 检查是否配置了远程代理
func (c *NodeConfig) HasRemoteProxy() bool {
	return c.RemoteProxy.SOCKS5 != "" || c.RemoteProxy.Fallback != ""
}

// GetSOCKS5Proxy 获取 SOCKS5 代理配置
func (c *NodeConfig) GetSOCKS5Proxy() string {
	return c.RemoteProxy.SOCKS5
}

// GetFallback 获取 Fallback 配置
func (c *NodeConfig) GetFallback() string {
	return c.RemoteProxy.Fallback
}

// ============================================================
// 【修复硬伤2】新增 ClientBehaviorConfig - 客户端行为配置
// ============================================================

// ClientBehaviorConfig 客户端行为配置
type ClientBehaviorConfig struct {
	Cadence         CadenceConfig `yaml:"cadence"`
	Cookies         CookiesConfig `yaml:"cookies"`
	FollowRedirects bool          `yaml:"follow_redirects"`
	MaxRedirects    int           `yaml:"max_redirects"`
}

// CadenceConfig 时序节奏配置
type CadenceConfig struct {
	Mode     string   `yaml:"mode"`      // none, browsing, fast, aggressive, random, custom, sequence
	MinDelay string   `yaml:"min_delay"` // 最小延迟
	MaxDelay string   `yaml:"max_delay"` // 最大延迟
	Sequence []string `yaml:"sequence"`  // 序列模式的延迟列表
	Jitter   float64  `yaml:"jitter"`    // 抖动系数
}

// CookiesConfig Cookie管理配置
type CookiesConfig struct {
	Enabled         bool `yaml:"enabled"`
	ClearOnRotation bool `yaml:"clear_on_rotation"` // 指纹轮换时是否清除Cookie
}

// ParseCadenceMode 解析时序模式配置为引擎可用的格式
func (c *CadenceConfig) ParseCadenceMode() string {
	if c.Mode == "" {
		return "none"
	}
	return c.Mode
}

// ParseMinDelay 解析最小延迟
func (c *CadenceConfig) ParseMinDelay() time.Duration {
	if c.MinDelay == "" {
		return 0
	}
	d, _ := time.ParseDuration(c.MinDelay)
	return d
}

// ParseMaxDelay 解析最大延迟
func (c *CadenceConfig) ParseMaxDelay() time.Duration {
	if c.MaxDelay == "" {
		return 0
	}
	d, _ := time.ParseDuration(c.MaxDelay)
	return d
}

// ParseSequence 解析延迟序列
func (c *CadenceConfig) ParseSequence() []time.Duration {
	result := make([]time.Duration, 0, len(c.Sequence))
	for _, s := range c.Sequence {
		if d, err := time.ParseDuration(s); err == nil {
			result = append(result, d)
		}
	}
	return result
}

// ============================================================
// 【修复遗漏2】新增 APIConfig 和 HealthConfig
// ============================================================

// APIConfig API服务器配置
type APIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"` // 例如 "127.0.0.1:9090"
	Token   string `yaml:"token"`  // Bearer Token 认证
}

// HealthConfig 健康检查配置
type HealthConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Interval   string `yaml:"interval"`    // 检查间隔，例如 "5m"
	Timeout    string `yaml:"timeout"`     // 单次检查超时，例如 "10s"
	Threshold  int    `yaml:"threshold"`   // 连续失败多少次标记为 down
	DegradedMs int64  `yaml:"degraded_ms"` // 延迟超过多少毫秒标记为 degraded
	TestURL    string `yaml:"test_url"`    // 测试URL
}

// ParseInterval 解析健康检查间隔
func (h *HealthConfig) ParseInterval() time.Duration {
	if h.Interval == "" {
		return 5 * time.Minute
	}
	d, _ := time.ParseDuration(h.Interval)
	if d == 0 {
		return 5 * time.Minute
	}
	return d
}

// ParseTimeout 解析健康检查超时
func (h *HealthConfig) ParseTimeout() time.Duration {
	if h.Timeout == "" {
		return 10 * time.Second
	}
	d, _ := time.ParseDuration(h.Timeout)
	if d == 0 {
		return 10 * time.Second
	}
	return d
}

// ============================================================
// 【修复遗漏3】新增 ProxyIPPoolConfig
// ============================================================

// ProxyIPPoolConfig ProxyIP池配置
type ProxyIPPoolConfig struct {
	Enabled bool              `yaml:"enabled"`
	Mode    string            `yaml:"mode"` // round-robin, random, latency, weighted, failover
	Options ProxyIPOptions    `yaml:"options"`
	Entries []ProxyIPEntry    `yaml:"entries"`
}

// ProxyIPOptions ProxyIP选项
type ProxyIPOptions struct {
	CheckPeriod string `yaml:"check_period"` // 健康检查周期
	Timeout     string `yaml:"timeout"`      // 连接超时
	MaxFails    int    `yaml:"max_fails"`    // 最大失败次数
}

// ProxyIPEntry ProxyIP条目
type ProxyIPEntry struct {
	Address  string `yaml:"address"`
	SNI      string `yaml:"sni"`
	Weight   int    `yaml:"weight"`
	Region   string `yaml:"region"`
	Provider string `yaml:"provider"`
	Enabled  bool   `yaml:"enabled"`
}

// ============================================================
// 辅助方法
// ============================================================

// ParseRetryBaseDelay 解析重试基础延迟
func (r *RetryOpts) ParseBaseDelay() time.Duration {
	if r.BaseDelay == "" {
		return 500 * time.Millisecond
	}
	d, _ := time.ParseDuration(r.BaseDelay)
	if d == 0 {
		return 500 * time.Millisecond
	}
	return d
}

// ParseRetryMaxDelay 解析重试最大延迟
func (r *RetryOpts) ParseMaxDelay() time.Duration {
	if r.MaxDelay == "" {
		return 10 * time.Second
	}
	d, _ := time.ParseDuration(r.MaxDelay)
	if d == 0 {
		return 10 * time.Second
	}
	return d
}

// GetJitter 获取抖动系数，默认0.2
func (r *RetryOpts) GetJitter() float64 {
	if r.Jitter <= 0 {
		return 0.2
	}
	if r.Jitter > 1 {
		return 1.0
	}
	return r.Jitter
}

// ParseIdleTimeout 解析连接池空闲超时
func (p *PoolOpts) ParseIdleTimeout() time.Duration {
	if p.IdleTimeout == "" {
		return 120 * time.Second
	}
	d, _ := time.ParseDuration(p.IdleTimeout)
	if d == 0 {
		return 120 * time.Second
	}
	return d
}

// ParseMaxLifetime 解析连接池最大生命周期
func (p *PoolOpts) ParseMaxLifetime() time.Duration {
	if p.MaxLifetime == "" {
		return 10 * time.Minute
	}
	d, _ := time.ParseDuration(p.MaxLifetime)
	if d == 0 {
		return 10 * time.Minute
	}
	return d
}

// GetMaxIdle 获取最大空闲连接数
func (p *PoolOpts) GetMaxIdle() int {
	if p.MaxIdle <= 0 {
		return 10
	}
	return p.MaxIdle
}

// GetMaxPerKey 获取每个key的最大连接数
func (p *PoolOpts) GetMaxPerKey() int {
	if p.MaxPerKey <= 0 {
		return 3
	}
	return p.MaxPerKey
}
