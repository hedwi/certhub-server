package controllers

import (
	"archive/zip"
	"bytes"
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

func beginCertOperation(c *gin.Context, domain models.Domain, userID uint, renew bool) (*models.User, bool) {
	if err := services.VerifyChallengeCNAME(domain.Domain, domain.CNameTarget); err != nil {
		setDomainError(domain.ID, "error", err.Error())
		utils.RespondSuccess(c, gin.H{
			"status":  "failed",
			"message": err.Error(),
		})
		return nil, false
	}

	if renew {
		var existing models.Certificate
		if err := config.DB.Where("domain_id = ?", domain.ID).First(&existing).Error; err != nil {
			utils.RespondError(c, http.StatusNotFound, "No certificate found for this domain")
			return nil, false
		}
	}

	result := config.DB.Model(&models.Domain{}).
		Where("id = ? AND user_id = ? AND status NOT IN ?", domain.ID, userID, []string{"generating"}).
		Updates(map[string]interface{}{"status": "generating", "error_message": ""})
	if result.Error != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to update domain status")
		return nil, false
	}
	if result.RowsAffected == 0 {
		utils.RespondError(c, http.StatusConflict, "Certificate operation already in progress for this domain")
		return nil, false
	}

	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		setDomainError(domain.ID, "error", "user not found")
		utils.RespondError(c, http.StatusInternalServerError, "User not found")
		return nil, false
	}
	return &user, true
}

func writeCertificateZip(c *gin.Context, domainName string, cert *models.Certificate, keyPEM []byte) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	files := map[string][]byte{
		"cert.pem":      cert.CertPEM,
		"privkey.pem":   keyPEM,
		"chain.pem":     cert.Issuer,
		"fullchain.pem": append(append(cert.CertPEM, '\n'), cert.Issuer...),
	}
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			utils.RespondError(c, http.StatusInternalServerError, "Failed to create zip")
			return
		}
		if _, err := w.Write(content); err != nil {
			utils.RespondError(c, http.StatusInternalServerError, "Failed to write zip")
			return
		}
	}
	if err := zw.Close(); err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to finalize zip")
		return
	}

	filename := domainName + "-certificate.zip"
	c.Header("Content-Disposition", "attachment; filename=\""+filename+"\"")
	c.Data(http.StatusOK, "application/zip", buf.Bytes())
}
