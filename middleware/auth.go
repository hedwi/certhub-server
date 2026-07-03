package middleware

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/utils"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")

		if userID == nil {
			utils.RespondNeedLogin(c)
			c.Abort()
			return
		}

		c.Set("userID", userID)
		c.Next()
	}
}
