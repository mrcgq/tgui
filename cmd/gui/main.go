package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/user/tls-client/pkg/engine"
	"github.com/user/tls-client/pkg/fingerprint"
	"github.com/user/tls-client/pkg/inbound"
	applog "github.com/user/tls-client/pkg/log"
	"github.com/user/tls-client/pkg/outbound"
	"github.com/user/tls-client/pkg/verify"
)

// ========================================
// 全局状态
// ========================================

type AppState struct {
	// 玩法A状态
	proxyRunning   atomic.Bool
	socks5Server   *inbound.SOCKS5Server
	httpServer     *inbound.HTTPProxyServer
	tunnelManager  *outbound.TunnelManager
	proxyStopCh    chan struct{}

	// 统计
	totalConns     atomic.Int64
	totalBytes     atomic.Int64
	activeConns    atomic.Int64

	// 日志
	logBuffer      []string
	logMutex       sync.Mutex
	maxLogLines    int
}

var state = &AppState{
	maxLogLines: 500,
}

func (s *AppState) addLog(msg string) {
	s.logMutex.Lock()
	defer s.logMutex.Unlock()
	timestamp := time.Now().Format("15:04:05")
	s.logBuffer = append(s.logBuffer, fmt.Sprintf("[%s] %s", timestamp, msg))
	if len(s.logBuffer) > s.maxLogLines {
		s.logBuffer = s.logBuffer[len(s.logBuffer)-s.maxLogLines:]
	}
}

func (s *AppState) getLogs() string {
	s.logMutex.Lock()
	defer s.logMutex.Unlock()
	return strings.Join(s.logBuffer, "\n")
}

// ========================================
// 主程序入口
// ========================================

func main() {
	a := app.New()
	a.Settings().SetTheme(theme.DarkTheme())

	w := a.NewWindow("TLS-Client GUI v3.5")
	w.Resize(fyne.NewSize(900, 700))

	// 创建标签页
	tabs := container.NewAppTabs(
		container.NewTabItem("🚀 玩法A: 隧道代理", createPlayATab(w)),
		container.NewTabItem("🔬 玩法B: 引擎直连", createPlayBTab(w)),
		container.NewTabItem("🎭 指纹管理", createFingerprintTab()),
		container.NewTabItem("📊 状态监控", createStatusTab(w)),
		container.NewTabItem("📝 日志", createLogTab(w)),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	w.SetContent(tabs)
	w.ShowAndRun()
}

// ========================================
// 玩法A: 隧道代理模式
// ========================================

func createPlayATab(w fyne.Window) fyne.CanvasObject {
	// === 服务配置区 ===
	socks5AddrEntry := widget.NewEntry()
	socks5AddrEntry.SetText("127.0.0.1:1080")
	socks5AddrEntry.SetPlaceHolder("SOCKS5监听地址")

	httpAddrEntry := widget.NewEntry()
	httpAddrEntry.SetText("127.0.0.1:8080")
	httpAddrEntry.SetPlaceHolder("HTTP代理监听地址")

	// === 节点配置区 ===
	nodeAddrEntry := widget.NewEntry()
	nodeAddrEntry.SetText("172.67.170.151:443")
	nodeAddrEntry.SetPlaceHolder("CF优选IP或目标地址")

	sniEntry := widget.NewEntry()
	sniEntry.SetText("your-worker.workers.dev")
	sniEntry.SetPlaceHolder("SNI域名")

	wsPathEntry := widget.NewEntry()
	wsPathEntry.SetText("/?token=secret")
	wsPathEntry.SetPlaceHolder("WebSocket路径")

	// === 传输协议选择 ===
	transportSelect := widget.NewSelect([]string{"ws", "h2", "raw"}, nil)
	transportSelect.SetSelected("ws")

	// === 指纹选择 ===
	profileSelect := widget.NewSelect(fingerprint.List(), nil)
	profileSelect.SetSelected("chrome-126-win")

	// === Xlink借力配置 ===
	socks5ProxyEntry := widget.NewEntry()
	socks5ProxyEntry.SetPlaceHolder("user:pass@host:port (可选)")

	fallbackEntry := widget.NewEntry()
	fallbackEntry.SetPlaceHolder("fallback-host:port (可选)")

	// === 控制按钮 ===
	startBtn := widget.NewButton("▶ 启动代理", nil)
	startBtn.Importance = widget.HighImportance

	stopBtn := widget.NewButton("■ 停止代理", nil)
	stopBtn.Disable()

	statusLabel := widget.NewLabel("状态: 已停止")
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	// === 按钮逻辑 ===
	startBtn.OnTapped = func() {
		if state.proxyRunning.Load() {
			return
		}

		// 获取配置
		cfg := &ProxyConfig{
			SOCKS5Addr:  socks5AddrEntry.Text,
			HTTPAddr:    httpAddrEntry.Text,
			NodeAddr:    nodeAddrEntry.Text,
			SNI:         sniEntry.Text,
			WSPath:      wsPathEntry.Text,
			Transport:   transportSelect.Selected,
			Profile:     profileSelect.Selected,
			SOCKS5Proxy: socks5ProxyEntry.Text,
			Fallback:    fallbackEntry.Text,
		}

		err := startProxy(cfg)
		if err != nil {
			dialog.ShowError(err, w)
			state.addLog(fmt.Sprintf("启动失败: %v", err))
			return
		}

		state.proxyRunning.Store(true)
		statusLabel.SetText("状态: ✅ 运行中")
		startBtn.Disable()
		stopBtn.Enable()
		state.addLog("代理服务已启动")
	}

	stopBtn.OnTapped = func() {
		stopProxy()
		state.proxyRunning.Store(false)
		statusLabel.SetText("状态: ⏹ 已停止")
		startBtn.Enable()
		stopBtn.Disable()
		state.addLog("代理服务已停止")
	}

	// === 布局 ===
	form := container.NewVBox(
		widget.NewCard("🌐 本地代理设置", "",
			container.NewVBox(
				container.NewGridWithColumns(2,
					widget.NewLabel("SOCKS5地址:"),
					socks5AddrEntry,
					widget.NewLabel("HTTP代理地址:"),
					httpAddrEntry,
				),
			),
		),
		widget.NewCard("🎯 远程节点配置", "",
			container.NewVBox(
				container.NewGridWithColumns(2,
					widget.NewLabel("节点地址:"),
					nodeAddrEntry,
					widget.NewLabel("SNI:"),
					sniEntry,
					widget.NewLabel("WS路径:"),
					wsPathEntry,
					widget.NewLabel("传输协议:"),
					transportSelect,
					widget.NewLabel("指纹:"),
					profileSelect,
				),
			),
		),
		widget.NewCard("🔗 Xlink借力 (可选)", "",
			container.NewVBox(
				container.NewGridWithColumns(2,
					widget.NewLabel("SOCKS5代理:"),
					socks5ProxyEntry,
					widget.NewLabel("Fallback:"),
					fallbackEntry,
				),
			),
		),
		widget.NewSeparator(),
		container.NewHBox(
			startBtn,
			stopBtn,
			layout.NewSpacer(),
			statusLabel,
		),
	)

	return container.NewVScroll(form)
}

// ========================================
// 玩法B: 引擎直连模式
// ========================================

func createPlayBTab(w fyne.Window) fyne.CanvasObject {
	// === 目标配置 ===
	targetURLEntry := widget.NewEntry()
	targetURLEntry.SetText("https://tls.peet.ws/api/all")
	targetURLEntry.SetPlaceHolder("目标URL")

	methodSelect := widget.NewSelect([]string{"GET", "POST", "HEAD"}, nil)
	methodSelect.SetSelected("GET")

	// === 指纹配置 ===
	profileSelect := widget.NewSelect(fingerprint.List(), nil)
	profileSelect.SetSelected("chrome-126-win")

	// === 高级选项 ===
	cadenceSelect := widget.NewSelect([]string{
		"none", "browsing", "fast", "aggressive", "random",
	}, nil)
	cadenceSelect.SetSelected("browsing")

	enableCookies := widget.NewCheck("启用Cookie管理", nil)
	enableCookies.SetChecked(true)

	// === 结果显示 ===
	resultText := widget.NewMultiLineEntry()
	resultText.SetPlaceHolder("响应结果将显示在这里...")
	resultText.Wrapping = fyne.TextWrapWord
	resultText.SetMinRowsVisible(15)

	// === 发送按钮 ===
	sendBtn := widget.NewButton("🚀 发送请求", nil)
	sendBtn.Importance = widget.HighImportance

	progressBar := widget.NewProgressBarInfinite()
	progressBar.Hide()

	sendBtn.OnTapped = func() {
		targetURL := targetURLEntry.Text
		if targetURL == "" {
			dialog.ShowError(fmt.Errorf("请输入目标URL"), w)
			return
		}

		sendBtn.Disable()
		progressBar.Show()
		resultText.SetText("正在请求...")
		state.addLog(fmt.Sprintf("玩法B请求: %s [%s]", targetURL, profileSelect.Selected))

		go func() {
			result, err := sendDirectRequest(&DirectRequestConfig{
				URL:        targetURL,
				Method:     methodSelect.Selected,
				Profile:    profileSelect.Selected,
				Cadence:    cadenceSelect.Selected,
				UseCookies: enableCookies.Checked,
			})

			// 更新UI必须在主线程
			fyne.CurrentApp().Driver().CanvasForObject(resultText).Content().Refresh()
			
			if err != nil {
				resultText.SetText(fmt.Sprintf("❌ 请求失败:\n%v", err))
				state.addLog(fmt.Sprintf("请求失败: %v", err))
			} else {
				resultText.SetText(result)
				state.addLog("请求成功")
			}
			
			sendBtn.Enable()
			progressBar.Hide()
		}()
	}

	// === 布局 ===
	form := container.NewVBox(
		widget.NewCard("🎯 请求配置", "",
			container.NewVBox(
				container.NewGridWithColumns(2,
					widget.NewLabel("目标URL:"),
					targetURLEntry,
					widget.NewLabel("请求方法:"),
					methodSelect,
					widget.NewLabel("指纹:"),
					profileSelect,
				),
			),
		),
		widget.NewCard("⚙️ 高级选项", "",
			container.NewVBox(
				container.NewGridWithColumns(2,
					widget.NewLabel("时序模式:"),
					cadenceSelect,
				),
				enableCookies,
			),
		),
		container.NewHBox(sendBtn, progressBar),
		widget.NewSeparator(),
		widget.NewCard("📄 响应结果", "", resultText),
	)

	return container.NewVScroll(form)
}

// ========================================
// 指纹管理标签页
// ========================================

func createFingerprintTab() fyne.CanvasObject {
	// 指纹列表
	profiles := fingerprint.All()
	
	var items []fyne.CanvasObject
	items = append(items, widget.NewLabel(fmt.Sprintf("共 %d 个指纹配置", len(profiles))))
	items = append(items, widget.NewSeparator())

	// 按浏览器分组
	browsers := map[string][]*fingerprint.BrowserProfile{}
	for _, p := range profiles {
		browsers[p.Browser] = append(browsers[p.Browser], p)
	}

	for browser, profiles := range browsers {
		browserLabel := widget.NewLabel(fmt.Sprintf("🌐 %s (%d个)", strings.ToUpper(browser), len(profiles)))
		browserLabel.TextStyle = fyne.TextStyle{Bold: true}
		items = append(items, browserLabel)

		for _, p := range profiles {
			tags := ""
			if len(p.Tags) > 0 {
				tags = fmt.Sprintf(" [%s]", strings.Join(p.Tags, ", "))
			}
			profileLabel := widget.NewLabel(fmt.Sprintf("  • %s (%s)%s", p.Name, p.Platform, tags))
			items = append(items, profileLabel)
		}
		items = append(items, widget.NewSeparator())
	}

	return container.NewVScroll(container.NewVBox(items...))
}

// ========================================
// 状态监控标签页
// ========================================

func createStatusTab(w fyne.Window) fyne.CanvasObject {
	totalConnsLabel := widget.NewLabel("总连接数: 0")
	activeConnsLabel := widget.NewLabel("活跃连接: 0")
	totalBytesLabel := widget.NewLabel("总流量: 0 B")
	proxyStatusLabel := widget.NewLabel("代理状态: 停止")

	refreshBtn := widget.NewButton("🔄 刷新", nil)

	refreshBtn.OnTapped = func() {
		totalConnsLabel.SetText(fmt.Sprintf("总连接数: %d", state.totalConns.Load()))
		activeConnsLabel.SetText(fmt.Sprintf("活跃连接: %d", state.activeConns.Load()))
		totalBytesLabel.SetText(fmt.Sprintf("总流量: %s", formatBytes(state.totalBytes.Load())))
		if state.proxyRunning.Load() {
			proxyStatusLabel.SetText("代理状态: ✅ 运行中")
		} else {
			proxyStatusLabel.SetText("代理状态: ⏹ 停止")
		}
	}

	// 自动刷新
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if w.Canvas() != nil {
				refreshBtn.OnTapped()
			}
		}
	}()

	return container.NewVBox(
		widget.NewCard("📊 运行统计", "",
			container.NewVBox(
				totalConnsLabel,
				activeConnsLabel,
				totalBytesLabel,
				proxyStatusLabel,
			),
		),
		refreshBtn,
	)
}

// ========================================
// 日志标签页
// ========================================

func createLogTab(w fyne.Window) fyne.CanvasObject {
	logText := widget.NewMultiLineEntry()
	logText.Wrapping = fyne.TextWrapWord
	logText.SetMinRowsVisible(25)

	refreshBtn := widget.NewButton("🔄 刷新日志", func() {
		logText.SetText(state.getLogs())
	})

	clearBtn := widget.NewButton("🗑 清空日志", func() {
		state.logMutex.Lock()
		state.logBuffer = []string{}
		state.logMutex.Unlock()
		logText.SetText("")
	})

	// 自动刷新
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if w.Canvas() != nil {
				logText.SetText(state.getLogs())
			}
		}
	}()

	return container.NewBorder(
		container.NewHBox(refreshBtn, clearBtn),
		nil, nil, nil,
		container.NewVScroll(logText),
	)
}

// ========================================
// 核心功能实现
// ========================================

type ProxyConfig struct {
	SOCKS5Addr  string
	HTTPAddr    string
	NodeAddr    string
	SNI         string
	WSPath      string
	Transport   string
	Profile     string
	SOCKS5Proxy string
	Fallback    string
}

func startProxy(cfg *ProxyConfig) error {
	logger, err := applog.New("info")
	if err != nil {
		return fmt.Errorf("创建日志器失败: %w", err)
	}

	// 获取指纹
	profile := fingerprint.Get(cfg.Profile)
	if profile == nil {
		profile = fingerprint.MustGet(fingerprint.DefaultProfile())
	}

	// 创建节点配置
	nodeCfg := &outbound.NodeConfig{
		Name:           "gui-node",
		Address:        cfg.NodeAddr,
		SNI:            cfg.SNI,
		Profile:        profile,
		VerifyMode:     verify.ModeSNISkip,
		RemoteSOCKS5:   cfg.SOCKS5Proxy,
		RemoteFallback: cfg.Fallback,
	}

	// 创建隧道管理器
	state.tunnelManager = outbound.NewTunnelManager(nodeCfg, logger)

	// 连接处理函数
	onConnect := func(clientConn net.Conn, target, domain string) {
		state.totalConns.Add(1)
		state.activeConns.Add(1)
		defer state.activeConns.Add(-1)
		state.addLog(fmt.Sprintf("新连接: %s -> %s", domain, target))
		state.tunnelManager.HandleConnect(clientConn, target, domain)
	}

	// 启动SOCKS5服务器
	if cfg.SOCKS5Addr != "" {
		state.socks5Server = inbound.NewSOCKS5Server(cfg.SOCKS5Addr, logger, onConnect)
		if err := state.socks5Server.Start(); err != nil {
			return fmt.Errorf("启动SOCKS5失败: %w", err)
		}
		state.addLog(fmt.Sprintf("SOCKS5监听: %s", cfg.SOCKS5Addr))
	}

	// 启动HTTP代理服务器
	if cfg.HTTPAddr != "" {
		state.httpServer = inbound.NewHTTPProxyServer(cfg.HTTPAddr, logger, onConnect)
		if err := state.httpServer.Start(); err != nil {
			return fmt.Errorf("启动HTTP代理失败: %w", err)
		}
		state.addLog(fmt.Sprintf("HTTP代理监听: %s", cfg.HTTPAddr))
	}

	state.proxyStopCh = make(chan struct{})
	return nil
}

func stopProxy() {
	if state.proxyStopCh != nil {
		close(state.proxyStopCh)
	}
	if state.socks5Server != nil {
		state.socks5Server.Stop()
		state.socks5Server = nil
	}
	if state.httpServer != nil {
		state.httpServer.Stop()
		state.httpServer = nil
	}
	if state.tunnelManager != nil {
		state.tunnelManager.Close()
		state.tunnelManager = nil
	}
}

// ========================================
// 玩法B: 直接请求
// ========================================

type DirectRequestConfig struct {
	URL        string
	Method     string
	Profile    string
	Cadence    string
	UseCookies bool
}

func sendDirectRequest(cfg *DirectRequestConfig) (string, error) {
	profile := fingerprint.Get(cfg.Profile)
	if profile == nil {
		return "", fmt.Errorf("未知指纹: %s", cfg.Profile)
	}

	selector := &fingerprint.FixedSelector{Profile: profile}
	transport := engine.NewFingerprintTransport(selector)
	transport.VerifyMode = verify.ModeInsecure

	// 设置时序控制
	if cfg.Cadence != "none" {
		var cadenceCfg engine.CadenceConfig
		switch cfg.Cadence {
		case "browsing":
			cadenceCfg = engine.DefaultBrowsingCadence()
		case "fast":
			cadenceCfg = engine.DefaultFastCadence()
		default:
			cadenceCfg = engine.NoCadence()
		}
		transport.Cadence = engine.NewCadence(cadenceCfg)
	}

	// 设置Cookie管理
	if cfg.UseCookies {
		cm := engine.NewCookieManagerSimple()
		transport.CookieManager = cm
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(context.Background(), cfg.Method, cfg.URL, nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	startTime := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(startTime)

	if err != nil {
		return "", fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	result := fmt.Sprintf("=== 请求信息 ===\n")
	result += fmt.Sprintf("URL: %s\n", cfg.URL)
	result += fmt.Sprintf("方法: %s\n", cfg.Method)
	result += fmt.Sprintf("指纹: %s\n", cfg.Profile)
	result += fmt.Sprintf("耗时: %v\n", elapsed)
	result += fmt.Sprintf("\n=== 响应信息 ===\n")
	result += fmt.Sprintf("状态: %s\n", resp.Status)
	result += fmt.Sprintf("协议: %s\n", resp.Proto)
	result += fmt.Sprintf("\n=== 响应头 ===\n")
	for k, v := range resp.Header {
		result += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", "))
	}
	result += fmt.Sprintf("\n=== 响应体 (%d 字节) ===\n", len(body))
	
	// 限制显示长度
	bodyStr := string(body)
	if len(bodyStr) > 5000 {
		bodyStr = bodyStr[:5000] + "\n... (截断)"
	}
	result += bodyStr

	return result, nil
}

// ========================================
// 辅助函数
// ========================================

func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
