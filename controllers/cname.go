package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
)

type UpdateCnameInput struct {
	Provider string `json:"provider"`
	APIToken string `json:"apiToken"`
	ZoneID   string `json:"zoneId"`
}

func GetCname(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}
	utils.RespondSuccess(c, toCnameConfigDTO(domain))
}

func UpdateCname(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}

	var input UpdateCnameInput
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	updates := map[string]interface{}{}
	if input.Provider != "" {
		updates["dns_provider"] = input.Provider
	}
	if input.ZoneID != "" {
		updates["dns_zone_id"] = input.ZoneID
	}
	if len(updates) > 0 {
		config.DB.Model(&domain).Updates(updates)
		config.DB.Where("id = ?", domain.ID).First(&domain)
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
		config.DB.Model(&domain).Updates(map[string]interface{}{
			"status":        "error",
			"error_message": err.Error(),
		})
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
