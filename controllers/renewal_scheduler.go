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
		rollbackStuckGenerating(domain)
	}
}

func rollbackStuckGenerating(domain models.Domain) {
	var cert models.Certificate
	hasCert := config.DB.Where("domain_id = ?", domain.ID).First(&cert).Error == nil

	updates := map[string]interface{}{
		"generating_since": nil,
	}
	if hasCert {
		updates["status"] = "active"
		updates["error_message"] = ""
		slog.Warn("reset stuck generating domain to active",
			"domain", domain.Domain,
			"domain_id", domain.ID,
		)
	} else {
		updates["status"] = "error"
		updates["error_message"] = stuckGeneratingMessage
		slog.Warn("reset stuck generating domain to error",
			"domain", domain.Domain,
			"domain_id", domain.ID,
		)
	}

	if err := config.DB.Model(&models.Domain{}).Where("id = ?", domain.ID).Updates(updates).Error; err != nil {
		slog.Error("failed to reset stuck generating domain",
			"domain", domain.Domain,
			"domain_id", domain.ID,
			"error", err,
		)
	}
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

	if domain.CNameTarget == "" {
		slog.Warn("auto renewal skipped: cname target not configured", "domain", domain.Domain, "domain_id", domain.ID)
		return
	}

	if err := services.VerifyChallengeCNAME(domain.Domain, domain.CNameTarget); err != nil {
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

	slog.Info("auto renewal started", "domain", domain.Domain, "domain_id", domain.ID)
	go runCertJob(domain, *user, true)
}

// lockDomainForCertJob sets domain status to generating and loads the owning user.
// Stale generating locks (older than generating_timeout) may be taken over immediately.
func lockDomainForCertJob(domain models.Domain, requireExistingCert bool) (*models.User, error) {
	if requireExistingCert {
		var existing models.Certificate
		if err := config.DB.Where("domain_id = ?", domain.ID).First(&existing).Error; err != nil {
			return nil, err
		}
	}

	now := time.Now()
	staleBefore := now.Add(-config.Cfg.Renewal.GeneratingTimeoutDuration())

	result := config.DB.Model(&models.Domain{}).
		Where(`id = ? AND (
			status NOT IN ? OR
			(status = ? AND (generating_since IS NULL OR generating_since < ?))
		)`, domain.ID, []string{"generating"}, "generating", staleBefore).
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
	if err := config.DB.First(&user, domain.UserID).Error; err != nil {
		setDomainError(domain.ID, "error", "user not found")
		return nil, err
	}
	return &user, nil
}
