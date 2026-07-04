package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/utils"
)

const certIssueRateWindow = time.Hour

// CertIssueRateLimitMiddleware limits certificate issue and renew API calls per authenticated user.
// Must run after AuthMiddleware.
func CertIssueRateLimitMiddleware() gin.HandlerFunc {
	if !config.Cfg.RateLimit.CertIssueRateLimitEnabled() {
		return func(c *gin.Context) { c.Next() }
	}

	limit := config.Cfg.RateLimit.CertIssueRequestsPerHour()
	burst := certIssueBurst(limit)
	limiter := newKeyedRateLimiter(limit, certIssueRateWindow, burst)

	return func(c *gin.Context) {
		userID, ok := utils.GetUserID(c)
		if !ok {
			c.Next()
			return
		}
		key := strconv.FormatUint(uint64(userID), 10)
		if !limiter.allow(key) {
			utils.RespondError(c, http.StatusTooManyRequests,
				"Certificate issue rate limit exceeded; please try again later")
			c.Abort()
			return
		}
		c.Next()
	}
}

func certIssueBurst(limit int) int {
	if limit <= 1 {
		return 1
	}
	if limit < 3 {
		return limit
	}
	return 3
}
