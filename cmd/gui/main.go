package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/user/tls-client/pkg/engine"
	"github.com/user/tls-client/pkg/fingerprint"
	"github.com/user/tls-client/pkg/inbound"
	applog "github.com/user/tls-client/pkg/log"
	"github.com/user/tls-client/pkg/outbound"
	"github.com/user/tls-client/pkg/verify"
)

// =====================================================
// TLS-Client Web GUI v3.5 - 玩法A+B 融合客户端
// 纯 Go 实现，无 CGO 依赖，跨平台编译
// =====================================================

func main() {
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║       TLS-Client GUI v3.5 - Anti-Fingerprint Engine        ║")
	fmt.Println("║              玩法A + 玩法B 融合客户端                       ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")

	gui := NewWebGUI()

	// 启动Web服务器
	port := gui.FindAvailablePort(8899)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	fmt.Printf("\n🚀 启动Web GUI: http://%s\n", addr)
	fmt.Println("📌 请在浏览器中打开上述地址")
	fmt.Println("📌 按 Ctrl+C 退出程序\n")

	// 自动打开浏览器
	go func() {
		time.Sleep(800 * time.Millisecond)
		openBrowser(fmt.Sprintf("http://%s", addr))
	}()

	// 启动HTTP服务
	if err := http.ListenAndServe(addr, gui); err != nil {
		fmt.Printf("❌ 启动失败: %v\n", err)
		os.Exit(1)
	}
}

// =====================================================
// WebGUI 核心结构
// =====================================================

type WebGUI struct {
	mu sync.Mutex

	// 玩法A 状态
	proxyRunning bool
	socks5Server *inbound.SOCKS5Server
	httpServer   *inbound.HTTPProxyServer
	tunnel       *outbound.TunnelManager
	proxyConfig  ProxyConfig

	// 统计
	stats struct {
		TotalConns  int64
		TotalBytes  int64
		ActiveConns int64
		StartTime   time.Time
	}

	// 日志
	logs     []LogEntry
	logsLock sync.Mutex
}

type ProxyConfig struct {
	Address     string `json:"address"`
	SNI         string `json:"sni"`
	WSPath      string `json:"ws_path"`
	Listen      string `json:"listen"`
	HTTPListen  string `json:"http_listen"`
	Profile     string `json:"profile"`
	Transport   string `json:"transport"`
	VerifyMode  string `json:"verify_mode"`
	SOCKS5Proxy string `json:"socks5_proxy"`
	Fallback    string `json:"fallback"`
}

type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

func NewWebGUI() *WebGUI {
	g := &WebGUI{
		logs: make([]LogEntry, 0, 200),
	}
	g.stats.StartTime = time.Now()
	g.addLog("info", "TLS-Client GUI 已启动")
	return g
}

// =====================================================
// HTTP 路由
// =====================================================

func (g *WebGUI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		return
	}

	// API 路由
	switch {
	case r.URL.Path == "/api/fingerprints":
		g.apiFingerprints(w, r)
	case r.URL.Path == "/api/proxy/start":
		g.apiProxyStart(w, r)
	case r.URL.Path == "/api/proxy/stop":
		g.apiProxyStop(w, r)
	case r.URL.Path == "/api/proxy/status":
		g.apiProxyStatus(w, r)
	case r.URL.Path == "/api/request":
		g.apiRequest(w, r)
	case r.URL.Path == "/api/logs":
		g.apiLogs(w, r)
	case r.URL.Path == "/api/stats":
		g.apiStats(w, r)
	case r.URL.Path == "/api/logs/clear":
		g.apiLogsClear(w, r)
	case r.URL.Path == "/" || r.URL.Path == "/index.html":
		g.serveIndex(w, r)
	default:
		http.NotFound(w, r)
	}
}

// =====================================================
// API: 指纹列表
// =====================================================

func (g *WebGUI) apiFingerprints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	profiles := fingerprint.All()
	result := make([]map[string]interface{}, 0, len(profiles))

	browsers := make(map[string]int)
	platforms := make(map[string]int)

	for _, p := range profiles {
		result = append(result, map[string]interface{}{
			"name":     p.Name,
			"browser":  p.Browser,
			"platform": p.Platform,
			"version":  p.Version,
			"ua":       p.UserAgent,
			"h2fp":     p.H2Fingerprint(),
			"ja4h":     fingerprint.ComputeJA4H(p),
			"tags":     p.Tags,
		})
		browsers[p.Browser]++
		platforms[p.Platform]++
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"profiles":  result,
		"count":     len(result),
		"default":   fingerprint.DefaultProfile(),
		"browsers":  browsers,
		"platforms": platforms,
	})
}

// =====================================================
// API: 玩法A - 代理控制
// =====================================================

func (g *WebGUI) apiProxyStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Method not allowed"})
		return
	}

	var req ProxyConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.proxyRunning {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "代理已在运行"})
		return
	}

	// 验证参数
	if req.Address == "" || req.SNI == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "地址和SNI不能为空"})
		return
	}

	// 默认值
	if req.Listen == "" {
		req.Listen = "127.0.0.1:1080"
	}
	if req.Profile == "" {
		req.Profile = fingerprint.DefaultProfile()
	}
	if req.Transport == "" {
		req.Transport = "ws"
	}
	if req.VerifyMode == "" {
		req.VerifyMode = "sni-skip"
	}
	if req.WSPath == "" {
		req.WSPath = "/"
	}

	// 获取指纹
	profile := fingerprint.Get(req.Profile)
	if profile == nil {
		profile = fingerprint.MustGet(fingerprint.DefaultProfile())
		g.addLog("warn", fmt.Sprintf("指纹 %s 不存在，使用默认指纹 %s", req.Profile, profile.Name))
	}

	// 解析验证模式
	vmode, err := verify.ParseMode(req.VerifyMode)
	if err != nil {
		vmode = verify.ModeSNISkip
	}

	// 创建日志
	logger, _ := applog.New("info")

	// 创建节点配置
	node := &outbound.NodeConfig{
		Name:           "gui-node",
		Address:        req.Address,
		SNI:            req.SNI,
		Profile:        profile,
		VerifyMode:     vmode,
		RemoteSOCKS5:   req.SOCKS5Proxy,
		RemoteFallback: req.Fallback,
	}

	// 创建隧道管理器
	g.tunnel = outbound.NewTunnelManager(node, logger)

	// 连接处理函数
	onConnect := func(clientConn net.Conn, target, domain string) {
		atomic.AddInt64(&g.stats.TotalConns, 1)
		atomic.AddInt64(&g.stats.ActiveConns, 1)
		defer atomic.AddInt64(&g.stats.ActiveConns, -1)

		g.addLog("info", fmt.Sprintf("🔗 连接: %s → %s", domain, target))
		g.tunnel.HandleConnect(clientConn, target, domain)
	}

	// 启动SOCKS5服务器
	g.socks5Server = inbound.NewSOCKS5Server(req.Listen, logger, onConnect)
	if err := g.socks5Server.Start(); err != nil {
		g.addLog("error", fmt.Sprintf("启动SOCKS5失败: %v", err))
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": fmt.Sprintf("启动SOCKS5失败: %v", err)})
		return
	}

	// 启动HTTP代理 (可选)
	if req.HTTPListen != "" {
		g.httpServer = inbound.NewHTTPProxyServer(req.HTTPListen, logger, onConnect)
		if err := g.httpServer.Start(); err != nil {
			g.socks5Server.Stop()
			g.addLog("error", fmt.Sprintf("启动HTTP代理失败: %v", err))
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": fmt.Sprintf("启动HTTP代理失败: %v", err)})
			return
		}
	}

	g.proxyRunning = true
	g.proxyConfig = req
	g.stats.StartTime = time.Now()

	g.addLog("info", fmt.Sprintf("✅ 代理已启动"))
	g.addLog("info", fmt.Sprintf("   SOCKS5: %s", req.Listen))
	if req.HTTPListen != "" {
		g.addLog("info", fmt.Sprintf("   HTTP: %s", req.HTTPListen))
	}
	g.addLog("info", fmt.Sprintf("   目标: %s (SNI: %s)", req.Address, req.SNI))
	g.addLog("info", fmt.Sprintf("   指纹: %s (%s/%s)", profile.Name, profile.Browser, profile.Platform))
	g.addLog("info", fmt.Sprintf("   传输: %s", req.Transport))
	if req.SOCKS5Proxy != "" {
		g.addLog("info", fmt.Sprintf("   Xlink SOCKS5: %s", req.SOCKS5Proxy))
	}
	if req.Fallback != "" {
		g.addLog("info", fmt.Sprintf("   Xlink Fallback: %s", req.Fallback))
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "代理启动成功",
		"config":  req,
		"profile": map[string]string{
			"name":     profile.Name,
			"browser":  profile.Browser,
			"platform": profile.Platform,
		},
	})
}

func (g *WebGUI) apiProxyStop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.proxyRunning {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "代理未运行"})
		return
	}

	if g.socks5Server != nil {
		g.socks5Server.Stop()
		g.socks5Server = nil
	}
	if g.httpServer != nil {
		g.httpServer.Stop()
		g.httpServer = nil
	}
	if g.tunnel != nil {
		g.tunnel.Close()
		g.tunnel = nil
	}

	g.proxyRunning = false
	g.addLog("info", "⏹ 代理已停止")

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "代理已停止",
	})
}

func (g *WebGUI) apiProxyStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	g.mu.Lock()
	running := g.proxyRunning
	config := g.proxyConfig
	g.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"running": running,
		"config":  config,
	})
}

// =====================================================
// API: 玩法B - 直接请求
// =====================================================

type DirectRequest struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	Profile   string            `json:"profile"`
	Cadence   string            `json:"cadence"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Timeout   int               `json:"timeout"`
	FollowRed bool              `json:"follow_redirects"`
}

func (g *WebGUI) apiRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Method not allowed"})
		return
	}

	var req DirectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	// 默认值
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.Profile == "" {
		req.Profile = fingerprint.DefaultProfile()
	}
	if req.Timeout <= 0 {
		req.Timeout = 30
	}

	// 验证URL
	if req.URL == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "URL不能为空"})
		return
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		req.URL = "https://" + req.URL
	}

	// 获取指纹
	profile := fingerprint.Get(req.Profile)
	if profile == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": fmt.Sprintf("指纹 %s 不存在", req.Profile)})
		return
	}

	g.addLog("info", fmt.Sprintf("🔬 玩法B请求: %s %s", req.Method, req.URL))
	g.addLog("info", fmt.Sprintf("   指纹: %s (%s/%s)", profile.Name, profile.Browser, profile.Platform))
	if req.Cadence != "" && req.Cadence != "none" {
		g.addLog("info", fmt.Sprintf("   时序: %s", req.Cadence))
	}

	// 创建选择器
	selector := &fingerprint.FixedSelector{Profile: profile}

	// 创建反检测传输层
	transport := engine.NewFingerprintTransport(selector)
	transport.VerifyMode = verify.ModeInsecure

	// 设置时序
	switch req.Cadence {
	case "browsing":
		transport.Cadence = engine.NewCadence(engine.DefaultBrowsingCadence())
	case "fast":
		transport.Cadence = engine.NewCadence(engine.DefaultFastCadence())
	}

	defer transport.CloseIdleConnections()

	// 创建HTTP客户端
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(req.Timeout) * time.Second,
	}
	if !req.FollowRed {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// 创建请求
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Timeout)*time.Second)
	defer cancel()

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		g.addLog("error", fmt.Sprintf("创建请求失败: %v", err))
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	// 设置默认头
	httpReq.Header.Set("User-Agent", profile.UserAgent)
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7")
	httpReq.Header.Set("Accept-Encoding", "gzip, deflate, br")
	httpReq.Header.Set("Connection", "keep-alive")
	httpReq.Header.Set("Upgrade-Insecure-Requests", "1")

	// 设置自定义头
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// 发送请求
	start := time.Now()
	resp, err := client.Do(httpReq)
	elapsed := time.Since(start)

	if err != nil {
		g.addLog("error", fmt.Sprintf("❌ 请求失败: %v", err))
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error(), "elapsed_ms": elapsed.Milliseconds()})
		return
	}
	defer resp.Body.Close()

	// 读取响应
	body, _ := io.ReadAll(resp.Body)

	// 收集响应头
	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	// 截断body用于日志
	bodyPreview := string(body)
	if len(bodyPreview) > 200 {
		bodyPreview = bodyPreview[:200] + "..."
	}

	g.addLog("info", fmt.Sprintf("✅ 响应: %d %s (耗时: %dms, 大小: %d bytes)",
		resp.StatusCode, http.StatusText(resp.StatusCode), elapsed.Milliseconds(), len(body)))

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"status_code":  resp.StatusCode,
		"status":       resp.Status,
		"headers":      headers,
		"body":         string(body),
		"body_size":    len(body),
		"elapsed_ms":   elapsed.Milliseconds(),
		"profile":      req.Profile,
		"profile_info": map[string]string{"browser": profile.Browser, "platform": profile.Platform},
	})
}

// =====================================================
// API: 日志和统计
// =====================================================

func (g *WebGUI) apiLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	g.logsLock.Lock()
	logs := make([]LogEntry, len(g.logs))
	copy(logs, g.logs)
	g.logsLock.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"logs":    logs,
		"count":   len(logs),
	})
}

func (g *WebGUI) apiLogsClear(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	g.logsLock.Lock()
	g.logs = make([]LogEntry, 0, 200)
	g.logsLock.Unlock()

	g.addLog("info", "日志已清空")

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "日志已清空",
	})
}

func (g *WebGUI) apiStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	g.mu.Lock()
	running := g.proxyRunning
	g.mu.Unlock()

	uptime := time.Since(g.stats.StartTime)

	// 浏览器和平台统计
	profiles := fingerprint.All()
	browsers := make(map[string]int)
	platforms := make(map[string]int)
	for _, p := range profiles {
		browsers[p.Browser]++
		platforms[p.Platform]++
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":           true,
		"running":           running,
		"total_conns":       atomic.LoadInt64(&g.stats.TotalConns),
		"active_conns":      atomic.LoadInt64(&g.stats.ActiveConns),
		"total_bytes":       atomic.LoadInt64(&g.stats.TotalBytes),
		"uptime":            uptime.String(),
		"uptime_secs":       int(uptime.Seconds()),
		"fingerprint_count": len(profiles),
		"browsers":          browsers,
		"platforms":         platforms,
		"default_profile":   fingerprint.DefaultProfile(),
	})
}

func (g *WebGUI) addLog(level, message string) {
	entry := LogEntry{
		Time:    time.Now().Format("15:04:05"),
		Level:   level,
		Message: message,
	}

	g.logsLock.Lock()
	g.logs = append(g.logs, entry)
	if len(g.logs) > 200 {
		g.logs = g.logs[len(g.logs)-200:]
	}
	g.logsLock.Unlock()

	// 同时输出到控制台
	levelIcon := "ℹ️"
	switch level {
	case "error":
		levelIcon = "❌"
	case "warn":
		levelIcon = "⚠️"
	case "debug":
		levelIcon = "🔧"
	}
	fmt.Printf("[%s] %s %s\n", entry.Time, levelIcon, message)
}

// =====================================================
// 工具函数
// =====================================================

func (g *WebGUI) FindAvailablePort(start int) int {
	for port := start; port < start+100; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			ln.Close()
			return port
		}
	}
	return start
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	}
	if err != nil {
		fmt.Printf("⚠️ 无法自动打开浏览器，请手动访问: %s\n", url)
	}
}

// =====================================================
// HTML 界面
// =====================================================

func (g *WebGUI) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLS-Client GUI v3.5 - 玩法A+B融合</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0a0a1a 0%, #1a1a3a 50%, #0a1a2a 100%);
            min-height: 100vh;
            color: #e0e0e0;
            line-height: 1.6;
        }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        /* 头部 */
        header {
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, rgba(0,212,255,0.1) 0%, rgba(155,89,182,0.1) 100%);
            border-radius: 20px;
            margin-bottom: 30px;
            border: 1px solid rgba(0,212,255,0.2);
        }
        header h1 {
            font-size: 2.8em;
            background: linear-gradient(90deg, #00d4ff, #9b59b6, #00d4ff);
            background-size: 200% auto;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: shine 3s linear infinite;
            margin-bottom: 10px;
        }
        @keyframes shine {
            to { background-position: 200% center; }
        }
        header p { color: #888; font-size: 1.1em; }
        header .version {
            display: inline-block;
            background: linear-gradient(135deg, #00d4ff, #9b59b6);
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            margin-top: 10px;
        }
        
        /* 标签导航 */
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            justify-content: center;
        }
        .tab-btn {
            padding: 14px 28px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            color: #aaa;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 15px;
            font-weight: 500;
        }
        .tab-btn:hover {
            background: rgba(255,255,255,0.1);
            color: #fff;
            transform: translateY(-2px);
        }
        .tab-btn.active {
            background: linear-gradient(135deg, #00d4ff, #9b59b6);
            color: #fff;
            border-color: transparent;
            box-shadow: 0 8px 25px rgba(0,212,255,0.3);
        }
        
        .tab-content { display: none; animation: fadeIn 0.3s ease; }
        .tab-content.active { display: block; }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* 卡片 */
        .card {
            background: rgba(255,255,255,0.03);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.08);
            backdrop-filter: blur(10px);
        }
        .card h3 {
            color: #00d4ff;
            margin-bottom: 20px;
            font-size: 1.3em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card h3::before {
            content: '';
            width: 4px;
            height: 24px;
            background: linear-gradient(135deg, #00d4ff, #9b59b6);
            border-radius: 2px;
        }
        
        /* 表单 */
        .form-group {
            margin-bottom: 18px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #999;
            font-size: 14px;
            font-weight: 500;
        }
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 14px 16px;
            background: rgba(0,0,0,0.4);
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 10px;
            color: #fff;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
            outline: none;
            border-color: #00d4ff;
            box-shadow: 0 0 0 3px rgba(0,212,255,0.1);
        }
        .form-group input::placeholder { color: #555; }
        
        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        
        /* 按钮 */
        .btn {
            padding: 14px 35px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 600;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .btn-primary {
            background: linear-gradient(135deg, #00d4ff, #0095ff);
            color: #fff;
        }
        .btn-primary:hover:not(:disabled) {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0,212,255,0.4);
        }
        .btn-danger {
            background: linear-gradient(135deg, #ff6b6b, #ee5a24);
            color: #fff;
        }
        .btn-danger:hover:not(:disabled) {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(238,90,36,0.4);
        }
        .btn-success {
            background: linear-gradient(135deg, #2ecc71, #27ae60);
            color: #fff;
        }
        .btn-success:hover:not(:disabled) {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(46,204,113,0.4);
        }
        .btn-secondary {
            background: rgba(255,255,255,0.1);
            color: #fff;
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        /* 状态栏 */
        .status-bar {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 18px 25px;
            background: rgba(0,0,0,0.3);
            border-radius: 12px;
            margin-bottom: 25px;
            border: 1px solid rgba(255,255,255,0.05);
        }
        .status-indicator {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: #ff6b6b;
            box-shadow: 0 0 10px rgba(255,107,107,0.5);
        }
        .status-indicator.running {
            background: #2ecc71;
            box-shadow: 0 0 15px rgba(46,204,113,0.6);
            animation: pulse 2s ease-in-out infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }
        .status-text { font-weight: 500; }
        .status-text.running { color: #2ecc71; }
        .status-text.stopped { color: #ff6b6b; }
        
        /* 结果框 */
        .result-box {
            background: rgba(0,0,0,0.5);
            border-radius: 12px;
            padding: 20px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
            max-height: 450px;
            overflow: auto;
            white-space: pre-wrap;
            word-break: break-all;
            border: 1px solid rgba(255,255,255,0.05);
            line-height: 1.5;
        }
        .result-box::-webkit-scrollbar { width: 8px; }
        .result-box::-webkit-scrollbar-track { background: rgba(0,0,0,0.3); border-radius: 4px; }
        .result-box::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.2); border-radius: 4px; }
        
        /* 指纹网格 */
        .fingerprint-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
            max-height: 500px;
            overflow-y: auto;
            padding-right: 10px;
        }
        .fingerprint-card {
            background: rgba(0,0,0,0.3);
            border-radius: 12px;
            padding: 18px;
            border-left: 4px solid #00d4ff;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .fingerprint-card:hover {
            transform: translateX(5px);
            background: rgba(0,0,0,0.4);
        }
        .fingerprint-card h4 {
            color: #fff;
            margin-bottom: 8px;
            font-size: 1.05em;
        }
        .fingerprint-card .meta {
            color: #888;
            font-size: 12px;
            display: flex;
            gap: 15px;
        }
        .fingerprint-card.chrome { border-color: #4285f4; }
        .fingerprint-card.firefox { border-color: #ff7139; }
        .fingerprint-card.safari { border-color: #5ac8fa; }
        .fingerprint-card.edge { border-color: #0078d7; }
        
        /* 日志框 */
        .log-box {
            background: rgba(0,0,0,0.5);
            border-radius: 12px;
            padding: 15px;
            height: 400px;
            overflow-y: auto;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 12px;
            border: 1px solid rgba(255,255,255,0.05);
        }
        .log-entry {
            padding: 8px 12px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            display: flex;
            gap: 12px;
        }
        .log-entry:last-child { border-bottom: none; }
        .log-entry .time { color: #666; min-width: 70px; }
        .log-entry .level {
            min-width: 50px;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
        }
        .log-entry .level-info { color: #00d4ff; }
        .log-entry .level-error { color: #ff6b6b; }
        .log-entry .level-warn { color: #f39c12; }
        .log-entry .level-debug { color: #9b59b6; }
        .log-entry .message { color: #ccc; flex: 1; }
        
        /* 统计卡片 */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, rgba(0,0,0,0.4) 0%, rgba(0,0,0,0.2) 100%);
            border-radius: 16px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.05);
            transition: transform 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-card .icon { font-size: 2em; margin-bottom: 10px; }
        .stat-card .value {
            font-size: 2.2em;
            font-weight: 700;
            background: linear-gradient(135deg, #00d4ff, #9b59b6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .stat-card .label { color: #888; margin-top: 8px; font-size: 14px; }
        
        /* 响应式 */
        @media (max-width: 768px) {
            header h1 { font-size: 2em; }
            .tabs { gap: 8px; }
            .tab-btn { padding: 12px 20px; font-size: 14px; }
            .form-row { grid-template-columns: 1fr; }
        }
        
        /* 加载动画 */
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* 提示框 */
        .tooltip {
            position: relative;
        }
        .tooltip:hover::after {
            content: attr(data-tip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(0,0,0,0.9);
            color: #fff;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            white-space: nowrap;
            z-index: 100;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ TLS-Client GUI</h1>
            <p>Anti-Fingerprint Network Engine | 反指纹网络引擎</p>
            <span class="version">v3.5 完全体 - 玩法A+B融合</span>
        </header>
        
        <div class="tabs">
            <button class="tab-btn active" data-tab="playA">🚀 玩法A: 隧道代理</button>
            <button class="tab-btn" data-tab="playB">🔬 玩法B: 引擎直连</button>
            <button class="tab-btn" data-tab="fingerprints">🎭 指纹库</button>
            <button class="tab-btn" data-tab="status">📊 状态监控</button>
            <button class="tab-btn" data-tab="logs">📝 运行日志</button>
        </div>
        
        <!-- ==================== 玩法A: 隧道代理 ==================== -->
        <div id="playA" class="tab-content active">
            <div class="status-bar">
                <div class="status-indicator" id="proxyIndicator"></div>
                <span class="status-text stopped" id="proxyStatus">代理状态: 未运行</span>
                <div style="flex:1"></div>
                <span id="proxyProfile" style="color:#888;font-size:14px;"></span>
            </div>
            
            <div class="card">
                <h3>📡 节点配置</h3>
                <div class="form-row">
                    <div class="form-group">
                        <label>CF优选IP / 目标地址 *</label>
                        <input type="text" id="cfAddress" value="172.67.170.151:443" placeholder="IP:端口 或 域名:端口">
                    </div>
                    <div class="form-group">
                        <label>SNI (TLS服务器名称) *</label>
                        <input type="text" id="sni" placeholder="your-worker.workers.dev">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>WebSocket 路径</label>
                        <input type="text" id="wsPath" value="/" placeholder="/?token=xxx">
                    </div>
                    <div class="form-group">
                        <label>SOCKS5 本地监听</label>
                        <input type="text" id="socks5Listen" value="127.0.0.1:1080">
                    </div>
                    <div class="form-group">
                        <label>HTTP 本地监听 (可选)</label>
                        <input type="text" id="httpListen" placeholder="127.0.0.1:8080">
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h3>🎭 指纹与传输配置</h3>
                <div class="form-row">
                    <div class="form-group">
                        <label>浏览器指纹</label>
                        <select id="proxyProfile"></select>
                    </div>
                    <div class="form-group">
                        <label>传输协议</label>
                        <select id="transport">
                            <option value="ws">WebSocket (推荐)</option>
                            <option value="h2">HTTP/2 (实际为WS)</option>
                            <option value="raw">Raw TLS</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>TLS 验证模式</label>
                        <select id="verifyMode">
                            <option value="sni-skip">SNI-Skip (域前置核心)</option>
                            <option value="strict">严格验证</option>
                            <option value="insecure">不验证 (仅测试)</option>
                        </select>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h3>🔗 Xlink 借力配置 (高级)</h3>
                <div class="form-row">
                    <div class="form-group">
                        <label>远程 SOCKS5 代理 (Worker出站)</label>
                        <input type="text" id="xlinkSocks5" placeholder="user:pass@host:port">
                    </div>
                    <div class="form-group">
                        <label>Fallback 地址 (备用跳板)</label>
                        <input type="text" id="xlinkFallback" placeholder="host:port">
                    </div>
                </div>
                <p style="color:#666;font-size:13px;margin-top:10px;">
                    💡 Xlink 借力: 指挥 Worker 通过 SOCKS5 代理连接目标，或在直连失败时使用 Fallback 地址
                </p>
            </div>
            
            <div style="text-align:center;margin-top:25px;">
                <button class="btn btn-primary" id="startProxyBtn" onclick="toggleProxy()">
                    <span>▶</span> 启动代理
                </button>
            </div>
        </div>
        
        <!-- ==================== 玩法B: 引擎直连 ==================== -->
        <div id="playB" class="tab-content">
            <div class="card">
                <h3>🔬 发送伪装请求 (绕过WAF核心)</h3>
                <div class="form-row">
                    <div class="form-group" style="grid-column: 1 / -1;">
                        <label>目标 URL *</label>
                        <input type="text" id="targetUrl" value="https://tls.peet.ws/api/all" placeholder="https://example.com/api">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>请求方法</label>
                        <select id="reqMethod">
                            <option value="GET">GET</option>
                            <option value="POST">POST</option>
                            <option value="PUT">PUT</option>
                            <option value="DELETE">DELETE</option>
                            <option value="HEAD">HEAD</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>浏览器指纹</label>
                        <select id="reqProfile"></select>
                    </div>
                    <div class="form-group">
                        <label>时序模式 (Cadence)</label>
                        <select id="cadence">
                            <option value="none">无延迟 (最快)</option>
                            <option value="browsing">浏览模式 (1-5秒)</option>
                            <option value="fast">快速模式 (100-500ms)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>超时时间 (秒)</label>
                        <input type="number" id="reqTimeout" value="30" min="5" max="120">
                    </div>
                </div>
                <div style="text-align:center;margin-top:20px;">
                    <button class="btn btn-success" id="sendReqBtn" onclick="sendRequest()">
                        <span>🚀</span> 发送请求
                    </button>
                </div>
            </div>
            
            <div class="card">
                <h3>📋 响应结果</h3>
                <div id="responseInfo" style="display:none;margin-bottom:15px;padding:15px;background:rgba(0,0,0,0.3);border-radius:10px;">
                    <div style="display:flex;gap:30px;flex-wrap:wrap;">
                        <div><strong>状态:</strong> <span id="respStatus" style="color:#2ecc71">-</span></div>
                        <div><strong>耗时:</strong> <span id="respTime">-</span></div>
                        <div><strong>大小:</strong> <span id="respSize">-</span></div>
                        <div><strong>指纹:</strong> <span id="respProfile" style="color:#00d4ff">-</span></div>
                    </div>
                </div>
                <div class="result-box" id="responseResult">等待发送请求...</div>
            </div>
        </div>
        
        <!-- ==================== 指纹库 ==================== -->
        <div id="fingerprints" class="tab-content">
            <div class="card">
                <h3>🎭 可用指纹库 (<span id="fpCount">0</span> 个)</h3>
                <div style="margin-bottom:20px;">
                    <input type="text" id="fpSearch" placeholder="搜索指纹名称、浏览器、平台..."
                           style="width:100%;max-width:400px;" oninput="filterFingerprints()">
                </div>
                <div class="fingerprint-grid" id="fingerprintList"></div>
            </div>
            
            <div class="card" id="fpDetail" style="display:none;">
                <h3>📋 指纹详情</h3>
                <pre id="fpDetailContent" class="result-box"></pre>
            </div>
        </div>
        
        <!-- ==================== 状态监控 ==================== -->
        <div id="status" class="tab-content">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="icon">🔗</div>
                    <div class="value" id="statConns">0</div>
                    <div class="label">总连接数</div>
                </div>
                <div class="stat-card">
                    <div class="icon">⚡</div>
                    <div class="value" id="statActive">0</div>
                    <div class="label">活跃连接</div>
                </div>
                <div class="stat-card">
                    <div class="icon">⏱️</div>
                    <div class="value" id="statUptime">0s</div>
                    <div class="label">运行时间</div>
                </div>
                <div class="stat-card">
                    <div class="icon">🎭</div>
                    <div class="value" id="statFingerprints">0</div>
                    <div class="label">指纹数量</div>
                </div>
            </div>
            
            <div class="card">
                <h3>📊 指纹分布统计</h3>
                <div style="display:flex;gap:40px;flex-wrap:wrap;">
                    <div>
                        <h4 style="color:#888;margin-bottom:10px;">按浏览器</h4>
                        <div id="browserStats"></div>
                    </div>
                    <div>
                        <h4 style="color:#888;margin-bottom:10px;">按平台</h4>
                        <div id="platformStats"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- ==================== 运行日志 ==================== -->
        <div id="logs" class="tab-content">
            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;">
                    <h3 style="margin-bottom:0;">📝 运行日志</h3>
                    <button class="btn btn-secondary" onclick="clearLogs()">🗑️ 清空</button>
                </div>
                <div class="log-box" id="logBox"></div>
            </div>
        </div>
    </div>
    
    <script>
        // ==================== 全局变量 ====================
        let proxyRunning = false;
        let allFingerprints = [];
        
        // ==================== 初始化 ====================
        document.addEventListener('DOMContentLoaded', () => {
            initTabs();
            loadFingerprints();
            startPolling();
        });
        
        function initTabs() {
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                    btn.classList.add('active');
                    document.getElementById(btn.dataset.tab).classList.add('active');
                });
            });
        }
        
        // ==================== 指纹管理 ====================
        async function loadFingerprints() {
            try {
                const resp = await fetch('/api/fingerprints');
                const data = await resp.json();
                
                if (!data.success) return;
                
                allFingerprints = data.profiles;
                
                // 填充下拉框
                ['proxyProfile', 'reqProfile'].forEach(id => {
                    const select = document.getElementById(id);
                    select.innerHTML = '';
                    data.profiles.forEach(p => {
                        const opt = document.createElement('option');
                        opt.value = p.name;
                        opt.textContent = ` + "`${p.name} (${p.browser}/${p.platform})`" + `;
                        if (p.name === data.default) opt.selected = true;
                        select.appendChild(opt);
                    });
                });
                
                renderFingerprints(data.profiles);
                document.getElementById('fpCount').textContent = data.count;
                document.getElementById('statFingerprints').textContent = data.count;
                
                // 统计信息
                renderStats(data.browsers, 'browserStats', {chrome:'#4285f4',firefox:'#ff7139',safari:'#5ac8fa',edge:'#0078d7'});
                renderStats(data.platforms, 'platformStats', {windows:'#0078d7',macos:'#555',linux:'#f39c12',ios:'#5ac8fa',android:'#3ddc84'});
                
            } catch (e) {
                console.error('加载指纹失败:', e);
            }
        }
        
        function renderFingerprints(profiles) {
            const grid = document.getElementById('fingerprintList');
            grid.innerHTML = profiles.map(p => ` + "`" + `
                <div class="fingerprint-card ${p.browser}" onclick="showFpDetail('${p.name}')">
                    <h4>${p.name}</h4>
                    <div class="meta">
                        <span>🌐 ${p.browser}</span>
                        <span>💻 ${p.platform}</span>
                        <span>📌 v${p.version}</span>
                    </div>
                </div>
            ` + "`" + `).join('');
        }
        
        function filterFingerprints() {
            const q = document.getElementById('fpSearch').value.toLowerCase();
            const filtered = allFingerprints.filter(p => 
                p.name.toLowerCase().includes(q) ||
                p.browser.toLowerCase().includes(q) ||
                p.platform.toLowerCase().includes(q)
            );
            renderFingerprints(filtered);
        }
        
        function showFpDetail(name) {
            const p = allFingerprints.find(f => f.name === name);
            if (!p) return;
            
            document.getElementById('fpDetail').style.display = 'block';
            document.getElementById('fpDetailContent').textContent = JSON.stringify(p, null, 2);
        }
        
        function renderStats(stats, elemId, colors) {
            const elem = document.getElementById(elemId);
            elem.innerHTML = Object.entries(stats).map(([k,v]) => ` + "`" + `
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                    <span style="width:12px;height:12px;border-radius:3px;background:${colors[k]||'#666'}"></span>
                    <span style="min-width:80px;">${k}</span>
                    <span style="color:#00d4ff;font-weight:600;">${v}</span>
                </div>
            ` + "`" + `).join('');
        }
        
        // ==================== 代理控制 ====================
        async function toggleProxy() {
            const btn = document.getElementById('startProxyBtn');
            btn.disabled = true;
            
            try {
                if (proxyRunning) {
                    const resp = await fetch('/api/proxy/stop', { method: 'POST' });
                    const data = await resp.json();
                    if (data.success) {
                        setProxyState(false);
                    } else {
                        alert('停止失败: ' + data.error);
                    }
                } else {
                    const config = {
                        address: document.getElementById('cfAddress').value,
                        sni: document.getElementById('sni').value,
                        ws_path: document.getElementById('wsPath').value,
                        listen: document.getElementById('socks5Listen').value,
                        http_listen: document.getElementById('httpListen').value,
                        profile: document.getElementById('proxyProfile').value,
                        transport: document.getElementById('transport').value,
                        verify_mode: document.getElementById('verifyMode').value,
                        socks5_proxy: document.getElementById('xlinkSocks5').value,
                        fallback: document.getElementById('xlinkFallback').value
                    };
                    
                    const resp = await fetch('/api/proxy/start', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config)
                    });
                    const data = await resp.json();
                    
                    if (data.success) {
                        setProxyState(true, config);
                    } else {
                        alert('启动失败: ' + data.error);
                    }
                }
            } catch (e) {
                alert('操作失败: ' + e.message);
            }
            
            btn.disabled = false;
        }
        
        function setProxyState(running, config) {
            proxyRunning = running;
            const btn = document.getElementById('startProxyBtn');
            const indicator = document.getElementById('proxyIndicator');
            const status = document.getElementById('proxyStatus');
            const profile = document.getElementById('proxyProfile');
            
            if (running) {
                btn.innerHTML = '<span>⏹</span> 停止代理';
                btn.className = 'btn btn-danger';
                indicator.classList.add('running');
                status.textContent = '代理状态: 运行中 (' + config.listen + ')';
                status.className = 'status-text running';
                profile.textContent = '指纹: ' + config.profile;
            } else {
                btn.innerHTML = '<span>▶</span> 启动代理';
                btn.className = 'btn btn-primary';
                indicator.classList.remove('running');
                status.textContent = '代理状态: 未运行';
                status.className = 'status-text stopped';
                profile.textContent = '';
            }
        }
        
        // ==================== 玩法B请求 ====================
        async function sendRequest() {
            const btn = document.getElementById('sendReqBtn');
            const resultBox = document.getElementById('responseResult');
            const infoBox = document.getElementById('responseInfo');
            
            btn.disabled = true;
            btn.innerHTML = '<span class="loading"></span> 请求中...';
            resultBox.textContent = '正在发送请求...';
            infoBox.style.display = 'none';
            
            try {
                const config = {
                    url: document.getElementById('targetUrl').value,
                    method: document.getElementById('reqMethod').value,
                    profile: document.getElementById('reqProfile').value,
                    cadence: document.getElementById('cadence').value,
                    timeout: parseInt(document.getElementById('reqTimeout').value) || 30
                };
                
                const resp = await fetch('/api/request', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                const data = await resp.json();
                
                if (data.success) {
                    infoBox.style.display = 'block';
                    document.getElementById('respStatus').textContent = data.status;
                    document.getElementById('respStatus').style.color = data.status_code < 400 ? '#2ecc71' : '#ff6b6b';
                    document.getElementById('respTime').textContent = data.elapsed_ms + 'ms';
                    document.getElementById('respSize').textContent = formatBytes(data.body_size);
                    document.getElementById('respProfile').textContent = data.profile + ' (' + data.profile_info.browser + ')';
                    
                    // 尝试格式化JSON
                    let body = data.body;
                    try {
                        body = JSON.stringify(JSON.parse(data.body), null, 2);
                    } catch {}
                    resultBox.textContent = body;
                } else {
                    resultBox.textContent = '❌ 请求失败: ' + data.error + '\\n\\n耗时: ' + (data.elapsed_ms || 0) + 'ms';
                }
            } catch (e) {
                resultBox.textContent = '❌ 请求异常: ' + e.message;
            }
            
            btn.disabled = false;
            btn.innerHTML = '<span>🚀</span> 发送请求';
        }
        
        // ==================== 日志 ====================
        async function updateLogs() {
            try {
                const resp = await fetch('/api/logs');
                const data = await resp.json();
                if (!data.success) return;
                
                const box = document.getElementById('logBox');
                const wasAtBottom = box.scrollHeight - box.scrollTop <= box.clientHeight + 50;
                
                box.innerHTML = data.logs.map(log => ` + "`" + `
                    <div class="log-entry">
                        <span class="time">${log.time}</span>
                        <span class="level level-${log.level}">${log.level}</span>
                        <span class="message">${escapeHtml(log.message)}</span>
                    </div>
                ` + "`" + `).join('');
                
                if (wasAtBottom) box.scrollTop = box.scrollHeight;
            } catch {}
        }
        
        async function clearLogs() {
            await fetch('/api/logs/clear', { method: 'POST' });
            updateLogs();
        }
        
        // ==================== 统计 ====================
        async function updateStats() {
            try {
                const resp = await fetch('/api/stats');
                const data = await resp.json();
                if (!data.success) return;
                
                document.getElementById('statConns').textContent = data.total_conns;
                document.getElementById('statActive').textContent = data.active_conns;
                document.getElementById('statUptime').textContent = formatUptime(data.uptime_secs);
                
                // 同步代理状态
                if (data.running !== proxyRunning) {
                    if (data.running) {
                        // 恢复代理状态显示
                        const statusResp = await fetch('/api/proxy/status');
                        const statusData = await statusResp.json();
                        if (statusData.running && statusData.config) {
                            setProxyState(true, statusData.config);
                        }
                    } else {
                        setProxyState(false);
                    }
                }
            } catch {}
        }
        
        // ==================== 轮询 ====================
        function startPolling() {
            updateLogs();
            updateStats();
            setInterval(updateLogs, 2000);
            setInterval(updateStats, 1000);
        }
        
        // ==================== 工具函数 ====================
        function formatBytes(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
            return (bytes/1024/1024).toFixed(2) + ' MB';
        }
        
        function formatUptime(secs) {
            if (secs < 60) return secs + 's';
            if (secs < 3600) return Math.floor(secs/60) + 'm ' + (secs%60) + 's';
            return Math.floor(secs/3600) + 'h ' + Math.floor((secs%3600)/60) + 'm';
        }
        
        function escapeHtml(str) {
            return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        }
    </script>
</body>
</html>`
