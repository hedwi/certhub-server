package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"golang.org/x/time/rate"
)

const (
	limiterIdleTTL         = 10 * time.Minute
	limiterCleanupInterval = 5 * time.Minute
)

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type keyedRateLimiter struct {
	entries map[string]*limiterEntry
	mu      sync.Mutex
	r       rate.Limit
	burst   int
}

func newKeyedRateLimiter(requests int, window time.Duration, burst int) *keyedRateLimiter {
	if requests <= 0 {
		requests = 1
	}
	if burst <= 0 {
		burst = requests
	}
	if burst > requests {
		burst = requests
	}
	l := &keyedRateLimiter{
		entries: make(map[string]*limiterEntry),
		r:       rate.Every(window / time.Duration(requests)),
		burst:   burst,
	}
	go l.runCleanup()
	return l
}

func (l *keyedRateLimiter) runCleanup() {
	ticker := time.NewTicker(limiterCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		l.evictStale(time.Now().Add(-limiterIdleTTL))
	}
}

func (l *keyedRateLimiter) evictStale(cutoff time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, entry := range l.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(l.entries, key)
		}
	}
}

func (l *keyedRateLimiter) allow(key string) bool {
	now := time.Now()

	l.mu.Lock()
	entry, ok := l.entries[key]
	if !ok {
		entry = &limiterEntry{
			limiter:  rate.NewLimiter(l.r, l.burst),
			lastSeen: now,
		}
		l.entries[key] = entry
	} else {
		entry.lastSeen = now
	}
	lim := entry.limiter
	l.mu.Unlock()

	return lim.Allow()
}

type ipRateLimiter struct {
	*keyedRateLimiter
}

func newIPRateLimiter(requestsPerMinute int) *ipRateLimiter {
	if requestsPerMinute <= 0 {
		requestsPerMinute = 60
	}
	return &ipRateLimiter{
		keyedRateLimiter: newKeyedRateLimiter(requestsPerMinute, time.Minute, requestsPerMinute),
	}
}

// RateLimitMiddleware limits requests per IP when enabled in config.
func RateLimitMiddleware() gin.HandlerFunc {
	if !config.Cfg.RateLimit.Enabled {
		return func(c *gin.Context) { c.Next() }
	}
	limiter := newIPRateLimiter(config.Cfg.RateLimit.RequestsPerMinute)
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded, please try again later"})
			c.Abort()
			return
		}
		c.Next()
	}
}
