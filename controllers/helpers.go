package controllers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/utils"
)

func parseDomainID(raw string) (uint, bool) {
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return uint(id), true
}

func requireUserID(c *gin.Context) (uint, bool) {
	userID, ok := utils.GetUserID(c)
	if !ok {
		utils.RespondNeedLogin(c)
		return 0, false
	}
	return userID, true
}

func getDomainOwned(c *gin.Context, domainIDStr string) (models.Domain, bool) {
	userID, ok := requireUserID(c)
	if !ok {
		return models.Domain{}, false
	}
	domainID, ok := parseDomainID(domainIDStr)
	if !ok {
		utils.RespondError(c, http.StatusBadRequest, "Invalid domain id")
		return models.Domain{}, false
	}
	var domain models.Domain
	if err := config.DB.Where("id = ? AND user_id = ?", domainID, userID).First(&domain).Error; err != nil {
		utils.RespondError(c, http.StatusNotFound, "Domain not found")
		return models.Domain{}, false
	}
	return domain, true
}

func loadCertificate(domainID uint) *models.Certificate {
	var cert models.Certificate
	if err := config.DB.Where("domain_id = ?", domainID).First(&cert).Error; err != nil {
		return nil
	}
	return &cert
}

func loadDomainDTO(domain models.Domain) DomainDTO {
	return toDomainDTO(domain, loadCertificate(domain.ID))
}
