package engine

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// CookieManager 管理 HTTP Cookie
type CookieManager struct {
	jar           http.CookieJar
	mu            sync.RWMutex
	enabled       bool
	cookiesSet    int64
	cookiesStored int64
}

// NewCookieManager 创建 Cookie 管理器
func NewCookieManager() (*CookieManager, error) {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}

	return &CookieManager{
		jar:     jar,
		enabled: true,
	}, nil
}

// NewCookieManagerSimple 创建简单的 Cookie 管理器
func NewCookieManagerSimple() *CookieManager {
	jar, _ := cookiejar.New(nil)
	return &CookieManager{
		jar:     jar,
		enabled: true,
	}
}

// SetEnabled 设置启用状态
func (cm *CookieManager) SetEnabled(enabled bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.enabled = enabled
}

// IsEnabled 检查是否启用
func (cm *CookieManager) IsEnabled() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.enabled
}

// SetCookies 设置 Cookie
func (cm *CookieManager) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if !cm.IsEnabled() || len(cookies) == 0 {
		return
	}

	cm.mu.Lock()
	cm.cookiesSet += int64(len(cookies))
	cm.mu.Unlock()

	cm.jar.SetCookies(u, cookies)
}

// Cookies 获取指定 URL 的 Cookie
func (cm *CookieManager) Cookies(u *url.URL) []*http.Cookie {
	if !cm.IsEnabled() {
		return nil
	}
	return cm.jar.Cookies(u)
}

// ApplyToRequest 将 Cookie 应用到请求
func (cm *CookieManager) ApplyToRequest(req *http.Request) {
	if !cm.IsEnabled() {
		return
	}

	cookies := cm.jar.Cookies(req.URL)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
}

// SaveFromResponse 从响应中保存 Cookie
func (cm *CookieManager) SaveFromResponse(resp *http.Response) {
	if !cm.IsEnabled() || resp == nil {
		return
	}

	cookies := resp.Cookies()
	if len(cookies) > 0 {
		cm.jar.SetCookies(resp.Request.URL, cookies)

		cm.mu.Lock()
		cm.cookiesStored += int64(len(cookies))
		cm.mu.Unlock()
	}
}

// Clear 清除所有 Cookie
func (cm *CookieManager) Clear() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return err
	}
	cm.jar = jar
	cm.cookiesSet = 0
	cm.cookiesStored = 0
	return nil
}

// Stats 返回统计信息
func (cm *CookieManager) Stats() map[string]int64 {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return map[string]int64{
		"cookies_set":    cm.cookiesSet,
		"cookies_stored": cm.cookiesStored,
	}
}

// CookieJar 返回底层的 http.CookieJar
func (cm *CookieManager) CookieJar() http.CookieJar {
	return cm.jar
}

// SessionCookie 创建会话 Cookie
func SessionCookie(name, value, domain, path string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     path,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// PersistentCookie 创建持久化 Cookie
func PersistentCookie(name, value, domain, path string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     path,
		MaxAge:   int(maxAge.Seconds()),
		Expires:  time.Now().Add(maxAge),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
