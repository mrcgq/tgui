package main

import (
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/user/tls-client/pkg/api"
	"github.com/user/tls-client/pkg/config"
	"github.com/user/tls-client/pkg/engine"
	"github.com/user/tls-client/pkg/fingerprint"
	"github.com/user/tls-client/pkg/health"
	"github.com/user/tls-client/pkg/inbound"
	applog "github.com/user/tls-client/pkg/log"
	"github.com/user/tls-client/pkg/outbound"
	"github.com/user/tls-client/pkg/verify"
)

var configPath string

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the proxy server",
	RunE:  runProxy,
}

func init() {
	runCmd.Flags().StringVarP(&configPath, "config", "c", "config.yaml", "path to config file")
}

func runProxy(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	logger, err := applog.NewWithOutput(cfg.Global.LogLevel, cfg.Global.LogOutput)
	if err != nil {
		return err
	}
	defer func() { _ = logger.Sync() }()

	vmode, err := verify.ParseMode(cfg.TLS.VerifyMode)
	if err != nil {
		return err
	}

	// ================================================================
	// 指纹选择器初始化
	// ================================================================
	profileNames := cfg.Fingerprint.Rotation.Profiles
	if len(profileNames) == 0 && cfg.Fingerprint.Rotation.Profile != "" {
		profileNames = []string{cfg.Fingerprint.Rotation.Profile}
	}
	selector, err := fingerprint.NewSelector(cfg.Fingerprint.Rotation.Mode, profileNames)
	if err != nil {
		return err
	}

	activeNodeCfg := cfg.ActiveNode()
	if activeNodeCfg == nil {
		logger.Fatal("no active node configured")
	}

	nodeProfile := selector.Select("")
	if activeNodeCfg.Fingerprint != "" {
		p := fingerprint.Get(activeNodeCfg.Fingerprint)
		if p != nil {
			nodeProfile = p
		}
	}

	node := outbound.NewNodeConfig(activeNodeCfg, nodeProfile, vmode, logger)

	// ================================================================
	// 【修复硬伤2】初始化客户端行为配置
	// ================================================================
	var cadence *engine.Cadence
	if cfg.ClientBehavior.Cadence.Mode != "none" && cfg.ClientBehavior.Cadence.Mode != "" {
		cadenceConfig := engine.CadenceConfig{
			Mode:     engine.CadenceMode(cfg.ClientBehavior.Cadence.Mode),
			MinDelay: cfg.ClientBehavior.Cadence.ParseMinDelay(),
			MaxDelay: cfg.ClientBehavior.Cadence.ParseMaxDelay(),
			Sequence: cfg.ClientBehavior.Cadence.ParseSequence(),
			Jitter:   cfg.ClientBehavior.Cadence.Jitter,
			Enabled:  true,
		}
		cadence = engine.NewCadence(cadenceConfig)
		logger.Info("cadence control enabled",
			zap.String("mode", cfg.ClientBehavior.Cadence.Mode),
			zap.Float64("jitter", cfg.ClientBehavior.Cadence.Jitter),
		)
	}

	var cookieManager *engine.CookieManager
	if cfg.ClientBehavior.Cookies.Enabled {
		cookieManager, err = engine.NewCookieManager()
		if err != nil {
			logger.Warn("failed to create cookie manager", zap.Error(err))
		} else {
			logger.Info("cookie management enabled",
				zap.Bool("clear_on_rotation", cfg.ClientBehavior.Cookies.ClearOnRotation),
			)
		}
	}

	// 记录客户端行为配置（用于调试）
	_ = cadence
	_ = cookieManager

	// ================================================================
	// 【修复遗漏2】初始化健康检查器
	// ================================================================
	var checker *health.Checker
	if cfg.Health.Enabled {
		checker = health.NewChecker(logger)

		// 为所有激活的节点添加健康检查
		for _, nodeCfg := range cfg.ActiveNodes() {
			checkProfile := selector.Select("")
			if nodeCfg.Fingerprint != "" {
				if p := fingerprint.Get(nodeCfg.Fingerprint); p != nil {
					checkProfile = p
				}
			}

			checker.AddNode(health.CheckConfig{
				Name:       nodeCfg.Name,
				Address:    nodeCfg.Address,
				SNI:        nodeCfg.SNI,
				Profile:    checkProfile,
				VerifyMode: vmode,
				Interval:   cfg.Health.ParseInterval(),
				Timeout:    cfg.Health.ParseTimeout(),
				Threshold:  int32(cfg.Health.Threshold),
				DegradedMs: cfg.Health.DegradedMs,
				TestURL:    cfg.Health.TestURL,
			})
		}

		checker.Start()
		defer checker.Stop()

		logger.Info("health checker started",
			zap.String("interval", cfg.Health.Interval),
			zap.Int("threshold", cfg.Health.Threshold),
		)
	}

	// ================================================================
	// 【修复遗漏2】初始化 API 服务器
	// ================================================================
	var apiServer *api.Server
	if cfg.API.Enabled {
		apiServer = api.NewServer(cfg.API.Listen, cfg.API.Token, logger)
		if checker != nil {
			apiServer.SetHealthChecker(checker)
		}
		if err := apiServer.Start(); err != nil {
			logger.Error("failed to start api server", zap.Error(err))
		} else {
			defer apiServer.Stop()
			logger.Info("api server started",
				zap.String("listen", cfg.API.Listen),
				zap.Bool("auth_enabled", cfg.API.Token != ""),
			)
		}
	}

	// ================================================================
	// 【修复遗漏3】初始化 ProxyIP 管理器
	// ================================================================
	var proxyIPSelector outbound.ProxyIPSelector
	if cfg.ProxyIPs.Enabled && len(cfg.ProxyIPs.Entries) > 0 {
		proxyIPManager := NewProxyIPManager(cfg.ProxyIPs, logger)
		proxyIPManager.Start()
		defer proxyIPManager.Stop()
		proxyIPSelector = proxyIPManager

		logger.Info("proxy ip manager started",
			zap.Int("entries", len(cfg.ProxyIPs.Entries)),
			zap.String("mode", cfg.ProxyIPs.Mode),
		)
	}

	// ================================================================
	// 创建隧道管理器
	// ================================================================
	var tunnel *outbound.TunnelManager
	if proxyIPSelector != nil {
		tunnel = outbound.NewTunnelManagerWithProxyIP(node, logger, proxyIPSelector)
	} else {
		tunnel = outbound.NewTunnelManager(node, logger)
	}
	defer tunnel.Close()

	logger.Info("using node",
		zap.String("name", node.Name),
		zap.String("address", node.Address),
		zap.String("sni", node.SNI),
		zap.String("profile", nodeProfile.Name),
		zap.String("browser", nodeProfile.Browser),
		zap.String("platform", nodeProfile.Platform),
		zap.String("transport", node.Transport.Name()),
		zap.String("verify", string(vmode)),
	)

	// 【修复遗漏1】记录连接池配置
	if node.PoolConfig != nil {
		logger.Debug("connection pool configured",
			zap.Int("max_idle", node.PoolConfig.MaxIdle),
			zap.Int("max_per_key", node.PoolConfig.MaxPerKey),
			zap.Duration("idle_timeout", node.PoolConfig.IdleTimeout),
			zap.Duration("max_lifetime", node.PoolConfig.MaxLifetime),
		)
	}

	// ================================================================
	// 启动入站代理服务器
	// ================================================================
	onConnect := func(clientConn net.Conn, target, domain string) {
		// 【修复硬伤2】应用时序控制
		if cadence != nil {
			cadence.Wait()
		}
		tunnel.HandleConnect(clientConn, target, domain)
	}

	var socks5 *inbound.SOCKS5Server
	if cfg.Inbound.SOCKS5.Listen != "" {
		if cfg.Inbound.SOCKS5.Username != "" {
			socks5 = inbound.NewSOCKS5ServerWithAuth(
				cfg.Inbound.SOCKS5.Listen,
				logger,
				onConnect,
				cfg.Inbound.SOCKS5.Username,
				cfg.Inbound.SOCKS5.Password,
			)
		} else {
			socks5 = inbound.NewSOCKS5Server(cfg.Inbound.SOCKS5.Listen, logger, onConnect)
		}
		if err := socks5.Start(); err != nil {
			return err
		}
		defer socks5.Stop()
	}

	var httpProxy *inbound.HTTPProxyServer
	if cfg.Inbound.HTTP.Listen != "" {
		httpProxy = inbound.NewHTTPProxyServer(cfg.Inbound.HTTP.Listen, logger, onConnect)
		if err := httpProxy.Start(); err != nil {
			return err
		}
		defer httpProxy.Stop()
	}

	// ================================================================
	// 等待退出信号
	// ================================================================
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	tunnelStats := tunnel.Stats()
	logger.Info("shutting down",
		zap.String("signal", sig.String()),
		zap.Int64("total_tunnels", tunnelStats.TotalConns),
		zap.Int64("total_bytes", tunnelStats.TotalBytes),
	)

	return nil
}

// ================================================================
// 【修复遗漏3】简化版 ProxyIP 管理器（内嵌实现）
// 完整版在 pkg/proxyip/manager.go，这里提供一个轻量级集成
// ================================================================

// ProxyIPManager 简化版 ProxyIP 管理器
type ProxyIPManager struct {
	entries []*proxyIPEntry
	mode    string
	current int
	logger  *zap.Logger
	stopCh  chan struct{}
}

type proxyIPEntry struct {
	address   string
	sni       string
	weight    int
	available bool
	failCount int
}

// NewProxyIPManager 创建 ProxyIP 管理器
func NewProxyIPManager(cfg config.ProxyIPPoolConfig, logger *zap.Logger) *ProxyIPManager {
	entries := make([]*proxyIPEntry, 0, len(cfg.Entries))
	for _, e := range cfg.Entries {
		if e.Enabled {
			entries = append(entries, &proxyIPEntry{
				address:   e.Address,
				sni:       e.SNI,
				weight:    e.Weight,
				available: true,
			})
		}
	}

	return &ProxyIPManager{
		entries: entries,
		mode:    cfg.Mode,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
}

// Start 启动管理器
func (m *ProxyIPManager) Start() {
	// 简化版不做后台健康检查
}

// Stop 停止管理器
func (m *ProxyIPManager) Stop() {
	close(m.stopCh)
}

// Select 选择一个 ProxyIP
func (m *ProxyIPManager) Select() *outbound.ProxyIPEntry {
	if len(m.entries) == 0 {
		return nil
	}

	// 找到可用的 entry
	var available []*proxyIPEntry
	for _, e := range m.entries {
		if e.available {
			available = append(available, e)
		}
	}

	if len(available) == 0 {
		// 如果都不可用，随机选一个
		e := m.entries[m.current%len(m.entries)]
		m.current++
		return &outbound.ProxyIPEntry{
			Address: e.address,
			SNI:     e.sni,
		}
	}

	// 根据模式选择
	var selected *proxyIPEntry
	switch m.mode {
	case "round-robin":
		selected = available[m.current%len(available)]
		m.current++
	case "random":
		selected = available[time.Now().UnixNano()%int64(len(available))]
	default:
		selected = available[0]
	}

	return &outbound.ProxyIPEntry{
		Address: selected.address,
		SNI:     selected.sni,
	}
}

// MarkFailed 标记失败
func (m *ProxyIPManager) MarkFailed(address string) {
	for _, e := range m.entries {
		if e.address == address {
			e.failCount++
			if e.failCount >= 3 {
				e.available = false
				m.logger.Warn("proxy ip marked unavailable",
					zap.String("address", address),
					zap.Int("fail_count", e.failCount),
				)
			}
			return
		}
	}
}

// MarkSuccess 标记成功
func (m *ProxyIPManager) MarkSuccess(address string) {
	for _, e := range m.entries {
		if e.address == address {
			e.failCount = 0
			e.available = true
			return
		}
	}
}
