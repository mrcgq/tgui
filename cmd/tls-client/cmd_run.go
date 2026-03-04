package main

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/user/tls-client/pkg/config"
	"github.com/user/tls-client/pkg/fingerprint"
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

	tunnel := outbound.NewTunnelManager(node, logger)
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

	onConnect := func(clientConn net.Conn, target, domain string) {
		tunnel.HandleConnect(clientConn, target, domain)
	}

	var socks5 *inbound.SOCKS5Server
	if cfg.Inbound.SOCKS5.Listen != "" {
		socks5 = inbound.NewSOCKS5Server(cfg.Inbound.SOCKS5.Listen, logger, onConnect)
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
