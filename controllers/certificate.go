package controllers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
)

type GenerateCertInput struct {
	DomainID uint `json:"domain_id" binding:"required"`
}

func setDomainError(domainID uint, status, message string) {
	config.DB.Model(&models.Domain{}).Where("id = ?", domainID).Updates(map[string]interface{}{
		"status":        status,
		"error_message": message,
	})
}

func runCertJob(domain models.Domain, user models.User, renew bool) {
	var certs *certificate.Resource
	var err error

	if renew {
		var existing models.Certificate
		if dbErr := config.DB.Where("domain_id = ?", domain.ID).First(&existing).Error; dbErr != nil {
			setDomainError(domain.ID, "error", "no existing certificate to renew")
			return
		}
		resource, buildErr := services.BuildCertResource(&existing)
		if buildErr != nil {
			setDomainError(domain.ID, "error", buildErr.Error())
			return
		}
		certs, err = services.RenewExistingCertificate(user.ID, user.Email, resource)
	} else {
		certs, err = services.ObtainCertificate(user.ID, domain.Domain, user.Email)
	}

	if err != nil {
		slog.Error("certificate operation failed", "domain", domain.Domain, "renew", renew, "error", err)
		setDomainError(domain.ID, "error", err.Error())
		return
	}

	expiresAt, err := services.ParseCertExpiry(certs.Certificate)
	if err != nil {
		slog.Warn("failed to parse cert expiry, using 90-day estimate", "domain", domain.Domain, "error", err)
		expiresAt = time.Now().AddDate(0, 0, 90)
	}

	encryptedKey, err := services.Encrypt(certs.PrivateKey)
	if err != nil {
		setDomainError(domain.ID, "error", "failed to encrypt private key")
		return
	}

	certRecord := models.Certificate{
		DomainID:      domain.ID,
		UserID:        user.ID,
		Domain:        domain.Domain,
		CertPEM:       certs.Certificate,
		KeyPEM:        encryptedKey,
		Issuer:        certs.IssuerCertificate,
		CertURL:       certs.CertURL,
		CertStableURL: certs.CertStableURL,
		ExpiresAt:     expiresAt,
	}

	config.DB.Where("domain_id = ?", domain.ID).Delete(&models.Certificate{})

	if err := config.DB.Create(&certRecord).Error; err != nil {
		slog.Error("failed to save certificate", "domain", domain.Domain, "error", err)
		setDomainError(domain.ID, "error", "failed to save certificate")
		return
	}

	config.DB.Model(&models.Domain{}).Where("id = ?", domain.ID).Updates(map[string]interface{}{
		"status":        "active",
		"error_message": "",
	})
	slog.Info("certificate saved", "domain", domain.Domain, "expires_at", expiresAt, "renew", renew)
}

func beginCertOperation(c *gin.Context, domainID, userID uint, renew bool) (*models.Domain, *models.User, bool) {
	var domain models.Domain
	if err := config.DB.Where("id = ? AND user_id = ?", domainID, userID).First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found or unauthorized"})
		return nil, nil, false
	}

	if err := services.VerifyChallengeCNAME(domain.Domain, domain.CNameTarget); err != nil {
		setDomainError(domain.ID, "error", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return nil, nil, false
	}

	if renew {
		var existing models.Certificate
		if err := config.DB.Where("domain_id = ?", domain.ID).First(&existing).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "No certificate found for this domain"})
			return nil, nil, false
		}
	}

	result := config.DB.Model(&models.Domain{}).
		Where("id = ? AND user_id = ? AND status NOT IN ?", domainID, userID, []string{"generating"}).
		Updates(map[string]interface{}{"status": "generating", "error_message": ""})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update domain status"})
		return nil, nil, false
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "Certificate operation already in progress for this domain"})
		return nil, nil, false
	}

	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		setDomainError(domain.ID, "error", "user not found")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return nil, nil, false
	}

	return &domain, &user, true
}

func GenerateCertificate(c *gin.Context) {
	var input GenerateCertInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, ok := utils.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domain, user, ok := beginCertOperation(c, input.DomainID, userID, false)
	if !ok {
		return
	}

	go runCertJob(*domain, *user, false)

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Certificate generation started. Poll GET /api/domains/:id for status.",
	})
}

func ListCertificates(c *gin.Context) {
	userID, ok := utils.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

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
	userID, ok := utils.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var cert models.Certificate
	if err := config.DB.Where("id = ? AND user_id = ?", certID, userID).First(&cert).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	keyPEM, err := services.Decrypt(cert.KeyPEM)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt private key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":      cert.Domain,
		"certificate": string(cert.CertPEM),
		"private_key": string(keyPEM),
		"issuer":      string(cert.Issuer),
		"expires_at":  cert.ExpiresAt,
	})
}

type RenewCertInput struct {
	DomainID uint `json:"domain_id" binding:"required"`
}

func RenewCertificate(c *gin.Context) {
	var input RenewCertInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, ok := utils.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domain, user, ok := beginCertOperation(c, input.DomainID, userID, true)
	if !ok {
		return
	}

	go runCertJob(*domain, *user, true)

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Certificate renewal started. Poll GET /api/domains/:id for status.",
	})
}
