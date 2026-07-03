package controllers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/utils"
	"gorm.io/gorm"
)

type DomainInput struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

func domainNameFromInput(input DomainInput) string {
	name := input.Name
	if name == "" {
		name = input.Domain
	}
	return normalizeDomain(name)
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func AddDomain(c *gin.Context) {
	var input DomainInput
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	userID, ok := requireUserID(c)
	if !ok {
		return
	}

	domainName := domainNameFromInput(input)
	if domainName == "" || strings.Contains(domainName, " ") {
		utils.RespondError(c, http.StatusBadRequest, "Invalid domain name")
		return
	}

	var existing models.Domain
	err := config.DB.Unscoped().Where("domain = ?", domainName).First(&existing).Error
	switch {
	case err == nil && !existing.DeletedAt.Valid:
		utils.RespondError(c, http.StatusConflict, "Domain already registered")
		return
	case err == nil && existing.UserID == userID:
		if err := restoreDeletedDomain(&existing); err != nil {
			utils.RespondError(c, http.StatusInternalServerError, "Failed to restore domain")
			return
		}
		if err := config.DB.Unscoped().First(&existing, existing.ID).Error; err != nil {
			utils.RespondError(c, http.StatusInternalServerError, "Failed to load restored domain")
			return
		}
		utils.RespondSuccess(c, loadDomainDTO(existing))
		return
	case err == nil:
		if err := permanentlyRemoveDomain(existing.ID); err != nil {
			utils.RespondError(c, http.StatusInternalServerError, "Failed to create domain")
			return
		}
	case !errors.Is(err, gorm.ErrRecordNotFound):
		utils.RespondError(c, http.StatusInternalServerError, "Failed to check domain")
		return
	}

	domain := models.Domain{
		UserID: userID,
		Domain: domainName,
		Status: "pending",
	}

	if err := config.DB.Create(&domain).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			utils.RespondError(c, http.StatusConflict, "Domain already registered")
			return
		}
		utils.RespondError(c, http.StatusInternalServerError, "Failed to create domain")
		return
	}

	delegationTarget := config.DelegationTarget(domain.ID)
	domain.CNameTarget = delegationTarget
	config.DB.Model(&domain).Update("cname_target", delegationTarget)

	utils.RespondSuccess(c, loadDomainDTO(domain))
}

func ListDomains(c *gin.Context) {
	userID, ok := requireUserID(c)
	if !ok {
		return
	}

	var domains []models.Domain
	if err := config.DB.Where("user_id = ?", userID).Order("created_at desc").Find(&domains).Error; err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to fetch domains")
		return
	}

	result := make([]DomainDTO, 0, len(domains))
	for _, d := range domains {
		result = append(result, loadDomainDTO(d))
	}
	utils.RespondSuccess(c, result)
}

func GetDomain(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}
	utils.RespondSuccess(c, loadDomainDTO(domain))
}

func DeleteDomain(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}

	if domain.Status == "generating" {
		utils.RespondError(c, http.StatusConflict, "Cannot delete domain while certificate generation is in progress")
		return
	}

	config.DB.Where("domain_id = ?", domain.ID).Delete(&models.Certificate{})
	config.DB.Where("domain_id = ?", domain.ID).Delete(&models.DeployTarget{})
	config.DB.Where("domain_id = ?", domain.ID).Delete(&models.DeployJob{})

	if err := config.DB.Delete(&domain).Error; err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to delete domain")
		return
	}

	utils.RespondSuccess(c, nil)
}

func restoreDeletedDomain(domain *models.Domain) error {
	return config.DB.Unscoped().Model(domain).Updates(map[string]interface{}{
		"deleted_at":       nil,
		"status":           "pending",
		"error_message":    "",
		"generating_since": nil,
	}).Error
}

func permanentlyRemoveDomain(domainID uint) error {
	config.DB.Unscoped().Where("domain_id = ?", domainID).Delete(&models.Certificate{})
	config.DB.Unscoped().Where("domain_id = ?", domainID).Delete(&models.DeployTarget{})
	config.DB.Unscoped().Where("domain_id = ?", domainID).Delete(&models.DeployJob{})
	return config.DB.Unscoped().Delete(&models.Domain{}, domainID).Error
}
