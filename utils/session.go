package utils

import "github.com/gin-gonic/gin"

// GetUserID retrieves the userID from the context and safely converts it to a uint
// This handles different underlying types that session stores might use (int, float64, uint)
func GetUserID(c *gin.Context) (uint, bool) {
	val, exists := c.Get("userID")
	if !exists {
		return 0, false
	}

	switch v := val.(type) {
	case uint:
		return v, true
	case int:
		return uint(v), true
	case float64:
		return uint(v), true
	default:
		return 0, false
	}
}
