package fingerprint

import (
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"sync"
	"time"
)

type Selector interface {
	Select(domain string) *BrowserProfile
}

type FixedSelector struct {
	Profile *BrowserProfile
}

func (s *FixedSelector) Select(_ string) *BrowserProfile {
	return s.Profile
}

type RandomSelector struct {
	Profiles []*BrowserProfile
	mu       sync.Mutex
}

func (s *RandomSelector) Select(_ string) *BrowserProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Profiles) == 0 {
		return nil
	}
	return s.Profiles[rand.IntN(len(s.Profiles))]
}

type PerDomainSelector struct {
	Profiles []*BrowserProfile
}

func (s *PerDomainSelector) Select(domain string) *BrowserProfile {
	if len(s.Profiles) == 0 {
		return nil
	}
	h := fnv.New64a()
	h.Write([]byte(domain))
	idx := int(h.Sum64()) % len(s.Profiles)
	return s.Profiles[idx]
}

type WeightedSelector struct {
	Profiles []*BrowserProfile
	Weights  []int
	total    int
	mu       sync.Mutex
}

func NewWeightedSelector(profiles []*BrowserProfile, weights []int) *WeightedSelector {
	if len(weights) < len(profiles) {
		padded := make([]int, len(profiles))
		copy(padded, weights)
		for i := len(weights); i < len(profiles); i++ {
			padded[i] = 1
		}
		weights = padded
	}
	total := 0
	for _, w := range weights {
		total += w
	}
	return &WeightedSelector{
		Profiles: profiles,
		Weights:  weights,
		total:    total,
	}
}

func (s *WeightedSelector) Select(_ string) *BrowserProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total == 0 || len(s.Profiles) == 0 {
		return nil
	}
	r := rand.IntN(s.total)
	for i, w := range s.Weights {
		r -= w
		if r < 0 {
			return s.Profiles[i]
		}
	}
	return s.Profiles[len(s.Profiles)-1]
}

type TimedRotationSelector struct {
	Profiles []*BrowserProfile
	Interval time.Duration
	startAt  time.Time
}

func NewTimedRotationSelector(profiles []*BrowserProfile, interval time.Duration) *TimedRotationSelector {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &TimedRotationSelector{
		Profiles: profiles,
		Interval: interval,
		startAt:  time.Now(),
	}
}

func (s *TimedRotationSelector) Select(_ string) *BrowserProfile {
	if len(s.Profiles) == 0 {
		return nil
	}
	elapsed := time.Since(s.startAt)
	idx := int(elapsed/s.Interval) % len(s.Profiles)
	return s.Profiles[idx]
}

func NewSelector(mode string, profileNames []string) (Selector, error) {
	profiles := make([]*BrowserProfile, 0, len(profileNames))
	for _, name := range profileNames {
		p := Get(name)
		if p == nil {
			return nil, fmt.Errorf("fingerprint: unknown profile %q", name)
		}
		profiles = append(profiles, p)
	}
	if len(profiles) == 0 {
		profiles = append(profiles, MustGet(DefaultProfile()))
	}

	switch mode {
	case "fixed", "":
		return &FixedSelector{Profile: profiles[0]}, nil
	case "random":
		return &RandomSelector{Profiles: profiles}, nil
	case "per-domain":
		return &PerDomainSelector{Profiles: profiles}, nil
	case "weighted":
		return NewWeightedSelector(profiles, nil), nil
	case "timed":
		return NewTimedRotationSelector(profiles, 5*time.Minute), nil
	default:
		return nil, fmt.Errorf("fingerprint: unknown rotation mode %q", mode)
	}
}
