package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
)

func GetCname(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}
	utils.RespondSuccess(c, toCnameConfigDTO(domain))
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

	if err := services.VerifyChallengeCNAME(domain.Domain, domain.CNameTarget); err != nil {
		utils.RespondSuccess(c, gin.H{
			"verified": false,
			"message":  err.Error(),
		})
		return
	}

	config.DB.Model(&domain).Updates(map[string]interface{}{
		"status":        "verified",
		"error_message": "",
	})

	utils.RespondSuccess(c, gin.H{
		"verified": true,
		"message":  "CNAME delegation verified; you may request a certificate",
	})
}
