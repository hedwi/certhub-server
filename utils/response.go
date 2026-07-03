package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	CodeSuccess   = 0
	CodeNeedLogin = 403
)

// APIResponse matches certhub-frontend SharedService.checkResponse expectations.
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Source  string      `json:"source,omitempty"`
}

// RespondNeedLogin tells the frontend to redirect to the login page.
// Returns HTTP 200 with code 403 so Angular invokes the success handler and checkResponse runs.
func RespondNeedLogin(c *gin.Context) {
	c.JSON(http.StatusOK, APIResponse{
		Code:    CodeNeedLogin,
		Message: "Unauthorized, please login",
	})
}

// RespondSuccess returns a standard success payload with code 0.
func RespondSuccess(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Code: CodeSuccess,
		Data: data,
	})
}

// RespondError returns an error payload. Uses HTTP 200 when keepHTTP200 is true so
// frontend success handlers can read the body; otherwise uses the given HTTP status.
func RespondError(c *gin.Context, httpStatus int, message string) {
	c.JSON(httpStatus, APIResponse{
		Code:    1,
		Message: message,
	})
}

// RespondMessage returns code 0 with a message payload for async operations.
func RespondMessage(c *gin.Context, payload interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Code: CodeSuccess,
		Data: payload,
	})
}
