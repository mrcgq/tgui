package fingerprint

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
)

var (
	mu       sync.RWMutex
	registry = make(map[string]*BrowserProfile)
)

func Register(p *BrowserProfile) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[p.Name]; exists {
		panic(fmt.Sprintf("fingerprint: duplicate profile name %q", p.Name))
	}
	registry[p.Name] = p
}

func RegisterValidated(p *BrowserProfile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[p.Name]; exists {
		return fmt.Errorf("fingerprint: duplicate profile name %q", p.Name)
	}
	registry[p.Name] = p
	return nil
}

func Get(name string) *BrowserProfile {
	mu.RLock()
	defer mu.RUnlock()
	return registry[name]
}

func MustGet(name string) *BrowserProfile {
	p := Get(name)
	if p == nil {
		panic(fmt.Sprintf("fingerprint: profile %q not found", name))
	}
	return p
}

func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func All() []*BrowserProfile {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]*BrowserProfile, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	return out
}

func Count() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(registry)
}

func Random() *BrowserProfile {
	all := All()
	if len(all) == 0 {
		return nil
	}
	return all[rand.IntN(len(all))]
}

func FilterByBrowser(browser string) []*BrowserProfile {
	mu.RLock()
	defer mu.RUnlock()
	var out []*BrowserProfile
	for _, p := range registry {
		if p.Browser == browser {
			out = append(out, p)
		}
	}
	return out
}

func FilterByPlatform(platform string) []*BrowserProfile {
	mu.RLock()
	defer mu.RUnlock()
	var out []*BrowserProfile
	for _, p := range registry {
		if p.Platform == platform {
			out = append(out, p)
		}
	}
	return out
}

func FilterByTag(tag string) []*BrowserProfile {
	mu.RLock()
	defer mu.RUnlock()
	var out []*BrowserProfile
	for _, p := range registry {
		if p.HasTag(tag) {
			out = append(out, p)
		}
	}
	return out
}

func DefaultProfile() string {
	return "chrome-126-win"
}
