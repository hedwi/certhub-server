package controllers

import (
	"archive/zip"
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
	"gorm.io/gorm"
)

func setDomainError(domainID uint, status, message string) {
	config.DB.Model(&models.Domain{}).Where("id = ?", domainID).Updates(map[string]interface{}{
		"status":           status,
		"error_message":    message,
		"generating_since": nil,
	})
}

// saveCertificateRecord upserts the certificate and marks the domain active in one transaction.
// On renewal, the existing row is updated in place so a failed save never deletes the old cert.
func saveCertificateRecord(domainID uint, certRecord models.Certificate) error {
	return config.DB.Transaction(func(tx *gorm.DB) error {
		var existing models.Certificate
		err := tx.Where("domain_id = ?", certRecord.DomainID).First(&existing).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if err := tx.Create(&certRecord).Error; err != nil {
				if errors.Is(err, gorm.ErrDuplicatedKey) {
					if err := tx.Where("domain_id = ?", certRecord.DomainID).First(&existing).Error; err != nil {
						return err
					}
					certRecord.ID = existing.ID
					certRecord.CreatedAt = existing.CreatedAt
					if err := tx.Save(&certRecord).Error; err != nil {
						return err
					}
					break
				}
				return err
			}
		case err != nil:
			return err
		default:
			certRecord.ID = existing.ID
			certRecord.CreatedAt = existing.CreatedAt
			if err := tx.Save(&certRecord).Error; err != nil {
				return err
			}
		}

		return tx.Model(&models.Domain{}).Where("id = ?", domainID).Updates(map[string]interface{}{
			"status":           "active",
			"error_message":    "",
			"generating_since": nil,
		}).Error
	})
}

func runCertJob(domain models.Domain, user models.User, renew bool) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("certificate job panicked",
				"domain", domain.Domain,
				"domain_id", domain.ID,
				"renew", renew,
				"panic", r,
				"stack", string(debug.Stack()),
			)
			setDomainError(domain.ID, "error", "internal error during certificate operation")
		}
	}()

	var certs *certificate.Resource
	var err error

	var existing models.Certificate
	hasExisting := config.DB.Where("domain_id = ?", domain.ID).First(&existing).Error == nil

	if renew || hasExisting {
		if !hasExisting {
			setDomainError(domain.ID, "error", "no existing certificate to renew")
			return
		}
		if !renew && hasExisting {
			slog.Warn("issue requested but certificate exists, using renew path", "domain", domain.Domain)
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

	if err := saveCertificateRecord(domain.ID, certRecord); err != nil {
		slog.Error("failed to save certificate", "domain", domain.Domain, "error", err)
		setDomainError(domain.ID, "error", "failed to save certificate")
		return
	}

	slog.Info("certificate saved", "domain", domain.Domain, "expires_at", expiresAt, "renew", renew)
}

func beginCertOperation(c *gin.Context, domain models.Domain, userID uint, renew bool) (*models.User, bool) {
	if err := services.VerifyChallengeCNAME(domain.Domain, domain.CNameTarget); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return nil, false
	}

	user, err := lockDomainForCertJob(domain, renew)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.RespondError(c, http.StatusNotFound, "No certificate found for this domain")
			return nil, false
		}
		if errors.Is(err, errCertOperationInProgress) {
			utils.RespondError(c, http.StatusConflict, "Certificate operation already in progress for this domain")
			return nil, false
		}
		utils.RespondError(c, http.StatusInternalServerError, "Failed to update domain status")
		return nil, false
	}
	return user, true
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
