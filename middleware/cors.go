package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
)

// CORSMiddleware allows browser clients on a different origin to send session cookies.
func CORSMiddleware() gin.HandlerFunc {
	allowedOrigins := config.Cfg.Server.AllowedOrigins
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}

		allowed := config.Cfg.Security.IsDevMode() && len(allowedOrigins) == 0
		for _, o := range allowedOrigins {
			if o == origin || o == "*" {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
