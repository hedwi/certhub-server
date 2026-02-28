package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub/config"
	"github.com/hedwi/certhub/models"
	"github.com/hedwi/certhub/services"
)

type GenerateCertInput struct {
	DomainID uint `json:"domain_id" binding:"required"`
}

func GenerateCertificate(c *gin.Context) {
	var input GenerateCertInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.MustGet("userID").(uint)

	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var domain models.Domain
	if err := config.DB.Where("id = ? AND user_id = ?", input.DomainID, userID).First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found or unauthorized"})
		return
	}

	domain.Status = "generating"
	config.DB.Save(&domain)

	// Goroutine for async generation to avoid timeout
	go func() {
		certs, err := services.ObtainCertificate(domain.Domain, user.Email)
		if err != nil {
			fmt.Printf("Failed to generate certificate for %s: %v\n", domain.Domain, err)
			domain.Status = "error"
			config.DB.Save(&domain)
			return
		}

		certificate := models.Certificate{
			DomainID:  domain.ID,
			UserID:    userID,
			Domain:    domain.Domain,
			CertPEM:   certs.Certificate,
			KeyPEM:    certs.PrivateKey,
			Issuer:    certs.IssuerCertificate,
			ExpiresAt: time.Now().AddDate(0, 3, 0), // Let's Encrypt certs are valid for 90 days.
		}

		config.DB.Where("domain_id = ?", domain.ID).Delete(&models.Certificate{})

		if err := config.DB.Create(&certificate).Error; err != nil {
			fmt.Printf("Failed to save certificate to database for %s: %v\n", domain.Domain, err)
			domain.Status = "error"
			config.DB.Save(&domain)
			return
		}

		domain.Status = "active"
		config.DB.Save(&domain)
		fmt.Printf("Successfully generated and saved certificate for %s\n", domain.Domain)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Certificate generation started in background. Check domain status later.",
	})
}

func ListCertificates(c *gin.Context) {
	userID := c.MustGet("userID").(uint)

	var certs []models.Certificate
	if err := config.DB.Where("user_id = ?", userID).Find(&certs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch certificates"})
		return
	}

	var res []interface{}
	for _, cert := range certs {
		res = append(res, gin.H{
			"id":         cert.ID,
			"domain_id":  cert.DomainID,
			"domain":     cert.Domain,
			"expires_at": cert.ExpiresAt,
			"created_at": cert.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"certificates": res})
}

func DownloadCertificate(c *gin.Context) {
	certID := c.Param("id")
	userID := c.MustGet("userID").(uint)

	var cert models.Certificate
	if err := config.DB.Where("id = ? AND user_id = ?", certID, userID).First(&cert).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":      cert.Domain,
		"certificate": string(cert.CertPEM),
		"private_key": string(cert.KeyPEM),
		"issuer":      string(cert.Issuer),
	})
}

type RenewCertInput struct {
	DomainID uint `json:"domain_id" binding:"required"`
}

func RenewCertificate(c *gin.Context) {
	// This can essentially do the same as generate cert using Lego's Renew function
	// For simplicity, we can just call Generate again as lego defaults to renewal if cert exists locally or we force it.
	// In our case we are storing in DB, obtaining a new fresh cert is effectively a renewal if it's near expiry.
	GenerateCertificate(c)
}
