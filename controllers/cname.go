package controllers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
)

func cnameLiveCheckEnabled(c *gin.Context) bool {
	switch strings.ToLower(strings.TrimSpace(c.DefaultQuery("live", "true"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func GetCname(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}

	var liveVerified *bool
	if cnameLiveCheckEnabled(c) && domain.CNameTarget != "" {
		err := services.VerifyChallengeCNAME(c.Request.Context(), domain.Domain, domain.CNameTarget)
		ok := err == nil
		liveVerified = &ok
	}

	utils.RespondSuccess(c, toCnameConfigDTO(domain, liveVerified))
}

func markDomainCnameVerified(domainID uint) error {
	now := time.Now()
	return config.DB.Model(&models.Domain{}).Where("id = ?", domainID).Updates(map[string]interface{}{
		"status":            "verified",
		"error_message":     "",
		"cname_verified_at": now,
	}).Error
}

func VerifyCname(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}

	if domain.CNameTarget == "" {
		utils.RespondSuccess(c, gin.H{
			"verified": false,
			"message":  "CNAME target not configured for this domain",
		})
		return
	}

	if err := services.VerifyChallengeCNAME(c.Request.Context(), domain.Domain, domain.CNameTarget); err != nil {
		utils.RespondSuccess(c, gin.H{
			"verified": false,
			"message":  err.Error(),
		})
		return
	}

	verifiedAt := time.Now()
	if err := markDomainCnameVerified(domain.ID); err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to update domain status")
		return
	}

	utils.RespondSuccess(c, gin.H{
		"verified":   true,
		"verifiedAt": verifiedAt.UTC().Format(time.RFC3339),
		"message":    "CNAME delegation verified; you may request a certificate",
	})
}
