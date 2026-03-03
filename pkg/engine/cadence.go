package engine

import (
	"math/rand"
	"sync"
	"time"
)

// CadenceMode 时序节奏模式
type CadenceMode string

const (
	CadenceModeNone       CadenceMode = "none"
	CadenceModeBrowsing   CadenceMode = "browsing"
	CadenceModeFast       CadenceMode = "fast"
	CadenceModeAggressive CadenceMode = "aggressive"
	CadenceModeCustom     CadenceMode = "custom"
	CadenceModeRandom     CadenceMode = "random"
)

// CadenceConfig 时序指纹配置
type CadenceConfig struct {
	Mode     CadenceMode
	MinDelay time.Duration
	MaxDelay time.Duration
	Sequence []time.Duration
	Jitter   float64
	Enabled  bool
}

// Cadence 时序控制器
type Cadence struct {
	config          CadenceConfig
	mu              sync.Mutex
	lastRequestTime time.Time
	sequenceIndex   int
	rng             *rand.Rand
}

// NewCadence 创建时序控制器
func NewCadence(config CadenceConfig) *Cadence {
	if !config.Enabled {
		config.Mode = CadenceModeNone
	}
	if config.Jitter < 0 {
		config.Jitter = 0
	}
	if config.Jitter > 1 {
		config.Jitter = 1
	}

	return &Cadence{
		config:          config,
		lastRequestTime: time.Now(),
		rng:             rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Wait 等待适当的时间后再发起下一个请求
func (c *Cadence) Wait() {
	if c.config.Mode == CadenceModeNone {
		return
	}

	delay := c.calculateDelay()
	if delay <= 0 {
		return
	}

	c.mu.Lock()
	elapsed := time.Since(c.lastRequestTime)
	c.mu.Unlock()

	if elapsed < delay {
		time.Sleep(delay - elapsed)
	}

	c.mu.Lock()
	c.lastRequestTime = time.Now()
	c.mu.Unlock()
}

func (c *Cadence) calculateDelay() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	var baseDelay time.Duration

	switch c.config.Mode {
	case CadenceModeNone:
		return 0
	case CadenceModeBrowsing:
		baseDelay = c.randomDuration(1*time.Second, 5*time.Second)
	case CadenceModeFast:
		baseDelay = c.randomDuration(100*time.Millisecond, 500*time.Millisecond)
	case CadenceModeAggressive:
		baseDelay = c.randomDuration(0, 100*time.Millisecond)
	case CadenceModeRandom:
		baseDelay = c.randomDuration(0, 10*time.Second)
	case CadenceModeCustom:
		if len(c.config.Sequence) > 0 {
			baseDelay = c.config.Sequence[c.sequenceIndex%len(c.config.Sequence)]
			c.sequenceIndex++
		}
	default:
		if c.config.MinDelay > 0 || c.config.MaxDelay > 0 {
			baseDelay = c.randomDuration(c.config.MinDelay, c.config.MaxDelay)
		}
	}

	if c.config.Jitter > 0 && baseDelay > 0 {
		jitter := time.Duration(float64(baseDelay) * c.config.Jitter * (c.rng.Float64()*2 - 1))
		baseDelay += jitter
		if baseDelay < 0 {
			baseDelay = 0
		}
	}

	return baseDelay
}

func (c *Cadence) randomDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(c.rng.Int63n(int64(max-min)))
}

// Reset 重置时序控制器
func (c *Cadence) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRequestTime = time.Now()
	c.sequenceIndex = 0
}

// SetMode 设置模式
func (c *Cadence) SetMode(mode CadenceMode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.Mode = mode
}

// SetEnabled 设置启用状态
func (c *Cadence) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.Enabled = enabled
	if !enabled {
		c.config.Mode = CadenceModeNone
	}
}

// DefaultBrowsingCadence 返回默认浏览模式配置
func DefaultBrowsingCadence() CadenceConfig {
	return CadenceConfig{
		Mode:    CadenceModeBrowsing,
		Jitter:  0.3,
		Enabled: true,
	}
}

// DefaultFastCadence 返回默认快速模式配置
func DefaultFastCadence() CadenceConfig {
	return CadenceConfig{
		Mode:    CadenceModeFast,
		Jitter:  0.2,
		Enabled: true,
	}
}

// NoCadence 返回无延迟配置
func NoCadence() CadenceConfig {
	return CadenceConfig{
		Mode:    CadenceModeNone,
		Enabled: false,
	}
}
