package h2

import (
	"fmt"
	"strings"

	"golang.org/x/net/http2"
)

// PriorityConfig HTTP/2 PRIORITY 帧配置
type PriorityConfig struct {
	StreamID  uint32
	Exclusive bool
	DependsOn uint32
	Weight    uint8
}

// FingerprintConfig HTTP/2 指纹配置
type FingerprintConfig struct {
	Settings          []http2.Setting
	WindowUpdateValue uint32
	PseudoHeaderOrder []string
	PriorityFrames    []PriorityConfig
	MaxFrameSize      uint32
	SendPriority      bool
}

// SettingsString 返回 SETTINGS 的字符串表示
func (c *FingerprintConfig) SettingsString() string {
	parts := make([]string, 0, len(c.Settings))
	for _, s := range c.Settings {
		parts = append(parts, fmt.Sprintf("%d:%d", s.ID, s.Val))
	}
	return strings.Join(parts, ";")
}

// PseudoOrderString 返回伪头顺序的字符串表示
func (c *FingerprintConfig) PseudoOrderString() string {
	return strings.Join(c.PseudoHeaderOrder, ",")
}

// Fingerprint 返回完整指纹字符串
func (c *FingerprintConfig) Fingerprint() string {
	return fmt.Sprintf("%s|%d|%s",
		c.SettingsString(),
		c.WindowUpdateValue,
		c.PseudoOrderString(),
	)
}

// InitialWindowSize 获取初始窗口大小
func (c *FingerprintConfig) InitialWindowSize() uint32 {
	for _, s := range c.Settings {
		if s.ID == http2.SettingInitialWindowSize {
			return s.Val
		}
	}
	return 65535
}

// GetMaxFrameSize 获取最大帧大小
func (c *FingerprintConfig) GetMaxFrameSize() uint32 {
	if c.MaxFrameSize > 0 {
		return c.MaxFrameSize
	}
	return 16384
}

// Validate 验证配置
func (c *FingerprintConfig) Validate() error {
	if len(c.Settings) == 0 {
		return fmt.Errorf("h2: settings cannot be empty")
	}
	if len(c.PseudoHeaderOrder) == 0 {
		return fmt.Errorf("h2: pseudo header order cannot be empty")
	}
	required := map[string]bool{
		":method": false, ":authority": false,
		":scheme": false, ":path": false,
	}
	for _, h := range c.PseudoHeaderOrder {
		if _, ok := required[h]; !ok {
			return fmt.Errorf("h2: unknown pseudo header %q", h)
		}
		required[h] = true
	}
	for h, found := range required {
		if !found {
			return fmt.Errorf("h2: missing required pseudo header %q", h)
		}
	}
	for _, pf := range c.PriorityFrames {
		if pf.StreamID == 0 {
			return fmt.Errorf("h2: priority frame stream ID cannot be 0")
		}
	}
	return nil
}

// GoDefaultConfig Go 默认配置
func GoDefaultConfig() FingerprintConfig {
	return FingerprintConfig{
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 4096},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingInitialWindowSize, Val: 4194304},
			{ID: http2.SettingMaxHeaderListSize, Val: 10485760},
		},
		WindowUpdateValue: 1073741823,
		PseudoHeaderOrder: []string{":method", ":path", ":scheme", ":authority"},
		SendPriority:      false,
	}
}

// ChromeDefaultConfig Chrome 126 默认配置
func ChromeDefaultConfig() FingerprintConfig {
	return FingerprintConfig{
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		},
		WindowUpdateValue: 15663105,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		MaxFrameSize:      16384,
		SendPriority:      true,
		PriorityFrames: []PriorityConfig{
			{StreamID: 3, Exclusive: true, DependsOn: 0, Weight: 200},
			{StreamID: 5, Exclusive: true, DependsOn: 0, Weight: 100},
			{StreamID: 7, Exclusive: true, DependsOn: 0, Weight: 0},
			{StreamID: 9, Exclusive: true, DependsOn: 7, Weight: 0},
			{StreamID: 11, Exclusive: true, DependsOn: 3, Weight: 0},
		},
	}
}

// FirefoxDefaultConfig Firefox 默认配置
func FirefoxDefaultConfig() FingerprintConfig {
	return FingerprintConfig{
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingInitialWindowSize, Val: 131072},
			{ID: http2.SettingMaxFrameSize, Val: 16384},
		},
		WindowUpdateValue: 12517377,
		PseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
		MaxFrameSize:      16384,
		SendPriority:      false,
	}
}

// SafariDefaultConfig Safari 默认配置
func SafariDefaultConfig() FingerprintConfig {
	return FingerprintConfig{
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 4096},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingMaxConcurrentStreams, Val: 100},
			{ID: http2.SettingInitialWindowSize, Val: 2097152},
			{ID: http2.SettingMaxFrameSize, Val: 16384},
		},
		WindowUpdateValue: 10420225,
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
		MaxFrameSize:      16384,
		SendPriority:      true,
		PriorityFrames: []PriorityConfig{
			{StreamID: 3, Exclusive: false, DependsOn: 0, Weight: 255},
			{StreamID: 5, Exclusive: false, DependsOn: 0, Weight: 255},
			{StreamID: 7, Exclusive: false, DependsOn: 0, Weight: 255},
		},
	}
}
