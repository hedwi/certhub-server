package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub/config"
	"github.com/hedwi/certhub/models"
	"github.com/hedwi/certhub/utils"
)

type DomainInput struct {
	Domain string `json:"domain" binding:"required"`
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

	// Check if domain already exists
	var existing models.Domain
	if err := config.DB.Where("domain = ?", input.Domain).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Domain already registered"})
		return
	}

	domain := models.Domain{
		UserID: userID,
		Domain: input.Domain,
		Status: "pending",
	}

	if err := config.DB.Create(&domain).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create domain"})
		return
	}

	cnameHost := "_acme-challenge." + input.Domain
	cnameTarget := config.Cfg.Domain.CNameTarget

	c.JSON(http.StatusCreated, gin.H{
		"message":      "Domain added successfully",
		"domain":       domain,
		"cname_host":   cnameHost,
		"cname_target": cnameTarget,
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
