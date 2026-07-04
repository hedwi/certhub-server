package controllers

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
	"gorm.io/gorm"
)

var certJobWG sync.WaitGroup

const cancelledCertJobMessage = "certificate operation was cancelled"

// StartCertJob runs a certificate operation asynchronously and tracks it for graceful shutdown.
// The caller must have acquired a cert job slot via tryAcquireCertJobSlot; the slot is released when the job finishes.
func StartCertJob(domain models.Domain, user models.User, renew, autoRenew bool) {
	ctx, token, release := beginCertJob(domain.ID)
	certJobWG.Add(1)
	go func() {
		workerDone := beginDomainWorker(domain.ID)
		defer workerDone()
		defer certJobWG.Done()
		defer release()
		defer releaseCertJobSlot()
		runCertJob(ctx, domain, user, renew, autoRenew, token)
	}()
}

// WaitCertJobs blocks until all in-flight certificate jobs finish or timeout elapses.
func WaitCertJobs(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		certJobWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

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
			"status":                   "active",
			"error_message":            "",
			"generating_since":         nil,
			"auto_renew_failures":      0,
			"auto_renew_backoff_until": nil,
		}).Error
	})
}

func domainHasCertificate(domainID uint) bool {
	var count int64
	config.DB.Model(&models.Certificate{}).Where("domain_id = ?", domainID).Count(&count)
	return count > 0
}

// setDomainAutoRenewFailure keeps the domain active when a valid certificate remains
// but records the renewal error for the UI and scheduler backoff.
func setDomainAutoRenewFailure(domainID uint, message string) {
	config.DB.Model(&models.Domain{}).Where("id = ?", domainID).Updates(map[string]interface{}{
		"status":           "active",
		"error_message":    message,
		"generating_since": nil,
	})
}

func failCertJob(domainID uint, message string, autoRenew bool) {
	if autoRenew && domainHasCertificate(domainID) {
		setDomainAutoRenewFailure(domainID, message)
		scheduleAutoRenewBackoff(domainID)
		return
	}
	setDomainError(domainID, "error", message)
	if autoRenew {
		scheduleAutoRenewBackoff(domainID)
	}
}

func failCertJobIfActive(domainID uint, token uint64, message string, autoRenew bool) {
	if !isCertJobActive(domainID, token) {
		slog.Info("skipping cert job failure for superseded job",
			"domain_id", domainID,
			"message", message,
		)
		return
	}
	failCertJob(domainID, message, autoRenew)
}

func runCertJob(ctx context.Context, domain models.Domain, user models.User, renew, autoRenew bool, token uint64) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("certificate job panicked",
				"domain", domain.Domain,
				"domain_id", domain.ID,
				"renew", renew,
				"auto_renew", autoRenew,
				"panic", r,
				"stack", string(debug.Stack()),
			)
			failCertJobIfActive(domain.ID, token, "internal error during certificate operation", autoRenew)
		}
	}()

	if err := ctx.Err(); err != nil {
		rollbackCancelledCertJob(domain.ID, token, autoRenew)
		return
	}

	if domain.CNameTarget == "" {
		failCertJobIfActive(domain.ID, token, "CNAME target not configured for this domain", autoRenew)
		return
	}
	if err := services.VerifyChallengeCNAME(ctx, domain.Domain, domain.CNameTarget); err != nil {
		failCertJobIfActive(domain.ID, token, err.Error(), autoRenew)
		return
	}

	var certs *certificate.Resource
	var err error

	acmeCtx := services.WithCertJobScope(ctx, func() bool {
		return isCertJobActive(domain.ID, token)
	})

	var existing models.Certificate
	hasExisting := config.DB.Where("domain_id = ?", domain.ID).First(&existing).Error == nil

	if renew || hasExisting {
		if !hasExisting {
			failCertJobIfActive(domain.ID, token, "no existing certificate to renew", autoRenew)
			return
		}
		if !renew && hasExisting {
			slog.Warn("issue requested but certificate exists, using renew path", "domain", domain.Domain)
		}
		resource, buildErr := services.BuildCertResource(&existing)
		if buildErr != nil {
			failCertJobIfActive(domain.ID, token, buildErr.Error(), autoRenew)
			return
		}
		certs, err = services.RenewExistingCertificate(acmeCtx, user.ID, user.Email, resource)
	} else {
		certs, err = services.ObtainCertificate(acmeCtx, user.ID, domain.Domain, user.Email)
	}

	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			slog.Info("certificate job cancelled",
				"domain", domain.Domain,
				"domain_id", domain.ID,
				"renew", renew,
				"auto_renew", autoRenew,
			)
			rollbackCancelledCertJob(domain.ID, token, autoRenew)
			return
		}
		slog.Error("certificate operation failed", "domain", domain.Domain, "renew", renew, "auto_renew", autoRenew, "error", err)
		failCertJobIfActive(domain.ID, token, err.Error(), autoRenew)
		return
	}

	if err := ctx.Err(); err != nil {
		rollbackCancelledCertJob(domain.ID, token, autoRenew)
		return
	}
	if !isCertJobActive(domain.ID, token) {
		slog.Info("skipping cert save for superseded job", "domain", domain.Domain, "domain_id", domain.ID)
		return
	}

	expiresAt, err := services.ParseCertExpiry(certs.Certificate)
	if err != nil {
		slog.Warn("failed to parse cert expiry, using 90-day estimate", "domain", domain.Domain, "error", err)
		expiresAt = time.Now().AddDate(0, 0, 90)
	}

	encryptedKey, err := services.Encrypt(certs.PrivateKey)
	if err != nil {
		failCertJobIfActive(domain.ID, token, "failed to encrypt private key", autoRenew)
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
		failCertJobIfActive(domain.ID, token, "failed to save certificate", autoRenew)
		return
	}

	slog.Info("certificate saved", "domain", domain.Domain, "expires_at", expiresAt, "renew", renew)
}

func beginCertOperation(c *gin.Context, domain models.Domain, userID uint, renew bool) (*models.User, bool) {
	if domain.CNameTarget == "" {
		utils.RespondError(c, http.StatusBadRequest, "CNAME target not configured for this domain")
		return nil, false
	}

	if err := services.VerifyChallengeCNAME(c.Request.Context(), domain.Domain, domain.CNameTarget); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return nil, false
	}

	if !renew && loadCertificate(domain.ID) == nil && domain.Status != "verified" {
		if err := markDomainCnameVerified(domain.ID); err != nil {
			utils.RespondError(c, http.StatusInternalServerError, "Failed to update domain status")
			return nil, false
		}
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

	if !tryAcquireCertJobSlot() {
		rollbackGeneratingDomain(domain.ID, "", true)
		utils.RespondError(c, http.StatusTooManyRequests, "Too many certificate operations in progress; try again later")
		return nil, false
	}
	return user, true
}

// rollbackCancelledCertJob resets a generating domain when its job was cancelled without a replacement.
func rollbackCancelledCertJob(domainID uint, token uint64, autoRenew bool) {
	if isCertJobActive(domainID, token) {
		return
	}
	if certJobInflight(domainID) {
		return
	}
	message := ""
	if autoRenew {
		message = cancelledCertJobMessage
	}
	rollbackGeneratingDomain(domainID, message, true)
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
