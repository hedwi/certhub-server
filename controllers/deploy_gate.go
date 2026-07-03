package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/utils"
)

const deployUnavailableMsg = "Deploy API is not available yet"

// requireDeployAPI gates deploy endpoints. Returns false when the API is disabled.
func requireDeployAPI(c *gin.Context) bool {
	if config.Cfg.Deploy.IsEnabled() {
		return true
	}
	utils.RespondError(c, http.StatusNotImplemented, deployUnavailableMsg)
	return false
}

// requireDeployExecution gates the deploy trigger endpoint when execution is not implemented.
func requireDeployExecution(c *gin.Context) bool {
	if !requireDeployAPI(c) {
		return false
	}
	utils.RespondError(c, http.StatusNotImplemented, "Certificate deploy execution is not implemented yet")
	return false
}
