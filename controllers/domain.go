package controllers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
)

type DomainInput struct {
	Domain string `json:"domain" binding:"required"`
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func AddDomain(c *gin.Context) {
	var input DomainInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, ok := utils.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainName := normalizeDomain(input.Domain)
	if domainName == "" || strings.Contains(domainName, " ") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain name"})
		return
	}

	var existing models.Domain
	if err := config.DB.Where("domain = ?", domainName).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Domain already registered"})
		return
	}

	domain := models.Domain{
		UserID: userID,
		Domain: domainName,
		Status: "pending",
	}

	if err := config.DB.Create(&domain).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create domain"})
		return
	}

	delegationTarget := config.DelegationTarget(domain.ID)
	domain.CNameTarget = delegationTarget
	config.DB.Model(&domain).Update("cname_target", delegationTarget)

	cnameHost := "_acme-challenge." + domainName

	c.JSON(http.StatusCreated, gin.H{
		"message":      "Domain added successfully",
		"domain":       domain,
		"cname_host":   cnameHost,
		"cname_target": delegationTarget,
		"instructions": "Create a CNAME record pointing " + cnameHost + " to " + delegationTarget,
	})
}

func VerifyDomain(c *gin.Context) {
	domainID := c.Param("id")
	userID, ok := utils.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var domain models.Domain
	if err := config.DB.Where("id = ? AND user_id = ?", domainID, userID).First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	if err := services.VerifyChallengeCNAME(domain.Domain, domain.CNameTarget); err != nil {
		config.DB.Model(&domain).Updates(map[string]interface{}{
			"status":        "error",
			"error_message": err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{
			"verified": false,
			"error":    err.Error(),
		})
		return
	}

	config.DB.Model(&domain).Updates(map[string]interface{}{
		"status":        "verified",
		"error_message": "",
	})

	c.JSON(http.StatusOK, gin.H{
		"verified": true,
		"message":  "CNAME delegation verified; you may request a certificate",
	})
}

func ListDomains(c *gin.Context) {
	userID, ok := utils.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var domains []models.Domain
	if err := config.DB.Where("user_id = ?", userID).Find(&domains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch domains"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"domains": domains})
}

func DeleteDomain(c *gin.Context) {
	domainID := c.Param("id")
	userID, ok := utils.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var domain models.Domain
	if err := config.DB.Where("id = ? AND user_id = ?", domainID, userID).First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	if domain.Status == "generating" {
		c.JSON(http.StatusConflict, gin.H{"error": "Cannot delete domain while certificate generation is in progress"})
		return
	}

	config.DB.Where("domain_id = ?", domain.ID).Delete(&models.Certificate{})

	if err := config.DB.Delete(&domain).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete domain"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Domain deleted successfully"})
}

func GetDomain(c *gin.Context) {
	domainID := c.Param("id")
	userID, ok := utils.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var domain models.Domain
	if err := config.DB.Where("id = ? AND user_id = ?", domainID, userID).First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"domain": domain})
}
