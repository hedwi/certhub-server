package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"golang.org/x/time/rate"
)

type ipRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.Mutex
	r        rate.Limit
	burst    int
}

func newIPRateLimiter(requestsPerMinute int) *ipRateLimiter {
	if requestsPerMinute <= 0 {
		requestsPerMinute = 60
	}
	return &ipRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		r:        rate.Every(time.Minute / time.Duration(requestsPerMinute)),
		burst:    requestsPerMinute,
	}
}

func (l *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.limiters[ip]
	if !ok {
		lim = rate.NewLimiter(l.r, l.burst)
		l.limiters[ip] = lim
	}
	return lim
}

// RateLimitMiddleware limits requests per IP when enabled in config.
func RateLimitMiddleware() gin.HandlerFunc {
	if !config.Cfg.RateLimit.Enabled {
		return func(c *gin.Context) { c.Next() }
	}
	limiter := newIPRateLimiter(config.Cfg.RateLimit.RequestsPerMinute)
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.getLimiter(ip).Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded, please try again later"})
			c.Abort()
			return
		}
		c.Next()
	}
}
