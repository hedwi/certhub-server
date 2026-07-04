package controllers

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/services"
	"gorm.io/gorm"
)

var errCertOperationInProgress = errors.New("certificate operation already in progress")

const stuckGeneratingMessage = "certificate operation timed out (server may have restarted); please retry"

// StartRenewalScheduler runs stuck-generating cleanup and, when enabled, auto-renewal scans.
func StartRenewalScheduler(ctx context.Context) {
	generatingTimeout := config.Cfg.Renewal.GeneratingTimeoutDuration()
	cleanupInterval := config.Cfg.Renewal.GeneratingCheckIntervalDuration()

	runStuckGeneratingCleanup(generatingTimeout)

	cleanupTicker := time.NewTicker(cleanupInterval)
	defer cleanupTicker.Stop()

	var renewalCh <-chan time.Time
	var renewalTicker *time.Ticker
	if config.Cfg.Renewal.IsEnabled() {
		interval, err := time.ParseDuration(config.Cfg.Renewal.CheckInterval)
		if err != nil {
			slog.Error("invalid renewal.check_interval, using 1h", "value", config.Cfg.Renewal.CheckInterval, "error", err)
			interval = time.Hour
		}
		renewalTicker = time.NewTicker(interval)
		defer renewalTicker.Stop()
		renewalCh = renewalTicker.C
		runRenewalScan()
		slog.Info("auto renewal scheduler started",
			"interval", interval,
			"renew_before_days", config.Cfg.Renewal.RenewBeforeDays,
			"generating_timeout", generatingTimeout,
			"generating_check_interval", cleanupInterval,
			"max_concurrent_cert_jobs", config.Cfg.Renewal.MaxConcurrentCertJobs(),
		)
	} else {
		slog.Info("auto renewal disabled; generating cleanup active",
			"generating_timeout", generatingTimeout,
			"generating_check_interval", cleanupInterval,
		)
	}

	for {
		select {
		case <-ctx.Done():
			slog.Info("scheduler stopped")
			return
		case <-cleanupTicker.C:
			runStuckGeneratingCleanup(generatingTimeout)
		case <-renewalCh:
			runRenewalScan()
		}
	}
}

func runStuckGeneratingCleanup(timeout time.Duration) {
	cutoff := time.Now().Add(-timeout)

	var stuck []models.Domain
	if err := config.DB.Where(
		"status = ? AND (generating_since IS NULL OR generating_since < ?)",
		"generating", cutoff,
	).Find(&stuck).Error; err != nil {
		slog.Error("stuck generating cleanup failed", "error", err)
		return
	}

	for _, domain := range stuck {
		if certJobInflight(domain.ID) {
			slog.Warn("cancelling timed-out cert job during stuck generating cleanup",
				"domain", domain.Domain,
				"domain_id", domain.ID,
			)
			cancelCertJob(domain.ID)
			waitDomainWorker(domain.ID, config.Cfg.Renewal.GeneratingTimeoutDuration())
		}
		rollbackStuckGenerating(domain, false)
	}
}

func rollbackStuckGenerating(domain models.Domain, force bool) {
	if !force && certJobInflight(domain.ID) {
		return
	}

	hasCert := domainHasCertificate(domain.ID)
	message := ""
	if !hasCert {
		message = stuckGeneratingMessage
	}
	rollbackGeneratingDomain(domain.ID, message, true)

	if hasCert {
		slog.Warn("reset stuck generating domain to active",
			"domain", domain.Domain,
			"domain_id", domain.ID,
		)
	} else {
		slog.Warn("reset stuck generating domain to error",
			"domain", domain.Domain,
			"domain_id", domain.ID,
		)
	}
}

// rollbackGeneratingDomain clears generating state after a cancelled or failed lock.
// When restoreVerified is true and the domain had CNAME verified, status returns to verified instead of error.
func rollbackGeneratingDomain(domainID uint, errorMessage string, restoreVerified bool) {
	var domain models.Domain
	if err := config.DB.First(&domain, domainID).Error; err != nil || domain.Status != "generating" {
		return
	}

	hasCert := domainHasCertificate(domainID)
	updates := map[string]interface{}{
		"generating_since": nil,
	}

	switch {
	case hasCert:
		updates["status"] = "active"
		if errorMessage != "" {
			updates["error_message"] = errorMessage
		} else {
			updates["error_message"] = ""
		}
	case restoreVerified && domain.CnameVerifiedAt != nil:
		updates["status"] = "verified"
		updates["error_message"] = ""
	default:
		updates["status"] = "error"
		if errorMessage == "" {
			errorMessage = cancelledCertJobMessage
		}
		updates["error_message"] = errorMessage
	}

	config.DB.Model(&models.Domain{}).Where("id = ?", domainID).Updates(updates)
}

func runRenewalScan() {
	renewBeforeDays := config.Cfg.Renewal.RenewBeforeDays
	if renewBeforeDays <= 0 {
		renewBeforeDays = 30
	}
	threshold := time.Now().AddDate(0, 0, renewBeforeDays)

	var certs []models.Certificate
	if err := config.DB.Where("expires_at <= ?", threshold).Find(&certs).Error; err != nil {
		slog.Error("auto renewal scan failed", "error", err)
		return
	}

	if len(certs) == 0 {
		return
	}

	slog.Info("auto renewal scan", "candidates", len(certs), "threshold", threshold.UTC().Format(time.RFC3339))

	for _, cert := range certs {
		var domain models.Domain
		if err := config.DB.First(&domain, cert.DomainID).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				slog.Warn("auto renewal: domain lookup failed", "domain_id", cert.DomainID, "error", err)
			}
			continue
		}
		tryAutoRenewDomain(domain)
	}
}

func tryAutoRenewDomain(domain models.Domain) {
	switch domain.Status {
	case "generating", "pending":
		return
	}

	if !domain.AutoRenew {
		return
	}

	if domain.AutoRenewBackoffUntil != nil && time.Now().Before(*domain.AutoRenewBackoffUntil) {
		slog.Debug("auto renewal skipped: in backoff",
			"domain", domain.Domain,
			"domain_id", domain.ID,
			"until", domain.AutoRenewBackoffUntil.UTC().Format(time.RFC3339),
			"failures", domain.AutoRenewFailures,
		)
		return
	}

	if domain.CNameTarget == "" {
		slog.Warn("auto renewal skipped: cname target not configured", "domain", domain.Domain, "domain_id", domain.ID)
		return
	}

	if err := services.VerifyChallengeCNAME(context.Background(), domain.Domain, domain.CNameTarget); err != nil {
		slog.Warn("auto renewal skipped: cname verify failed",
			"domain", domain.Domain,
			"domain_id", domain.ID,
			"error", err,
		)
		return
	}

	user, err := lockDomainForCertJob(domain, true)
	if err != nil {
		if errors.Is(err, errCertOperationInProgress) {
			slog.Debug("auto renewal skipped: operation in progress", "domain", domain.Domain, "domain_id", domain.ID)
			return
		}
		slog.Warn("auto renewal skipped: lock failed", "domain", domain.Domain, "domain_id", domain.ID, "error", err)
		return
	}

	if !tryAcquireCertJobSlot() {
		rollbackGeneratingDomain(domain.ID, "", true)
		slog.Debug("auto renewal skipped: concurrency limit reached",
			"domain", domain.Domain,
			"domain_id", domain.ID,
			"limit", config.Cfg.Renewal.MaxConcurrentCertJobs(),
		)
		return
	}

	slog.Info("auto renewal started", "domain", domain.Domain, "domain_id", domain.ID)
	StartCertJob(domain, *user, true, true)
}

// RollbackAllGeneratingDomains resets every domain stuck in generating (used on shutdown).
func RollbackAllGeneratingDomains() {
	var domains []models.Domain
	if err := config.DB.Where("status = ?", "generating").Find(&domains).Error; err != nil {
		slog.Error("shutdown rollback: list generating domains failed", "error", err)
		return
	}
	for _, domain := range domains {
		rollbackStuckGenerating(domain, true)
	}
}

func scheduleAutoRenewBackoff(domainID uint) {
	var domain models.Domain
	if err := config.DB.First(&domain, domainID).Error; err != nil {
		slog.Warn("auto renew backoff: domain lookup failed", "domain_id", domainID, "error", err)
		return
	}

	failures := domain.AutoRenewFailures + 1
	backoff := config.Cfg.Renewal.AutoRenewBackoffDuration(failures)
	until := time.Now().Add(backoff)

	if err := config.DB.Model(&models.Domain{}).Where("id = ?", domainID).Updates(map[string]interface{}{
		"auto_renew_failures":      failures,
		"auto_renew_backoff_until": until,
	}).Error; err != nil {
		slog.Warn("auto renew backoff: update failed", "domain_id", domainID, "error", err)
		return
	}

	slog.Info("auto renew backoff scheduled",
		"domain", domain.Domain,
		"domain_id", domainID,
		"failures", failures,
		"backoff", backoff,
		"until", until.UTC().Format(time.RFC3339),
	)
}

// lockDomainForCertJob sets domain status to generating and loads the owning user.
// Stale generating locks (older than generating_timeout) may be taken over after cancelling the prior job.
func lockDomainForCertJob(domain models.Domain, requireExistingCert bool) (*models.User, error) {
	if requireExistingCert {
		var existing models.Certificate
		if err := config.DB.Where("domain_id = ?", domain.ID).First(&existing).Error; err != nil {
			return nil, err
		}
	}

	var current models.Domain
	if err := config.DB.First(&current, domain.ID).Error; err != nil {
		return nil, err
	}

	now := time.Now()
	staleBefore := now.Add(-config.Cfg.Renewal.GeneratingTimeoutDuration())
	isStaleGenerating := current.Status == "generating" &&
		(current.GeneratingSince == nil || current.GeneratingSince.Before(staleBefore))

	if certJobInflight(current.ID) {
		if !isStaleGenerating {
			return nil, errCertOperationInProgress
		}
		slog.Warn("cancelling stale in-flight cert job before lock takeover",
			"domain", current.Domain,
			"domain_id", current.ID,
		)
		cancelCertJob(current.ID)
		if !waitDomainWorker(current.ID, config.Cfg.Renewal.GeneratingTimeoutDuration()) {
			return nil, errCertOperationInProgress
		}
	}

	result := config.DB.Model(&models.Domain{}).
		Where(`id = ? AND (
			status NOT IN ? OR
			(status = ? AND (generating_since IS NULL OR generating_since < ?))
		)`, current.ID, []string{"generating"}, "generating", staleBefore).
		Updates(map[string]interface{}{
			"status":           "generating",
			"error_message":    "",
			"generating_since": now,
		})
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, errCertOperationInProgress
	}

	var user models.User
	if err := config.DB.First(&user, current.UserID).Error; err != nil {
		setDomainError(current.ID, "error", "user not found")
		return nil, err
	}
	return &user, nil
}
