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

type ipRateLimiter struct {
	entries map[string]*limiterEntry
	mu      sync.Mutex
	r       rate.Limit
	burst   int
}

func newIPRateLimiter(requestsPerMinute int) *ipRateLimiter {
	if requestsPerMinute <= 0 {
		requestsPerMinute = 60
	}
	l := &ipRateLimiter{
		entries: make(map[string]*limiterEntry),
		r:       rate.Every(time.Minute / time.Duration(requestsPerMinute)),
		burst:   requestsPerMinute,
	}
	go l.runCleanup()
	return l
}

func (l *ipRateLimiter) runCleanup() {
	ticker := time.NewTicker(limiterCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		l.evictStale(time.Now().Add(-limiterIdleTTL))
	}
}

func (l *ipRateLimiter) evictStale(cutoff time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, entry := range l.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(l.entries, ip)
		}
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	now := time.Now()

	l.mu.Lock()
	entry, ok := l.entries[ip]
	if !ok {
		entry = &limiterEntry{
			limiter:  rate.NewLimiter(l.r, l.burst),
			lastSeen: now,
		}
		l.entries[ip] = entry
	} else {
		entry.lastSeen = now
	}
	lim := entry.limiter
	l.mu.Unlock()

	return lim.Allow()
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
