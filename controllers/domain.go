package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
	"gorm.io/gorm"
)

type DomainInput struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

type UpdateDomainInput struct {
	AutoRenew *bool `json:"autoRenew"`
}

var errDomainClaimLost = errors.New("domain claim lost")
var errDomainClaimCNAME = errors.New("domain claim cname verify failed")

func domainNameFromInput(input DomainInput) (string, error) {
	name := input.Name
	if name == "" {
		name = input.Domain
	}
	return utils.ValidateDomainName(name)
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

	domainName, err := domainNameFromInput(input)
	if err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	var existing models.Domain
	err = config.DB.Unscoped().Where("domain = ?", domainName).First(&existing).Error
	switch {
	case err == nil && !existing.DeletedAt.Valid:
		if existing.UserID == userID {
			utils.RespondError(c, http.StatusConflict, "Domain already registered")
			return
		}
		if isUnclaimedDomain(existing) {
			domain, err := claimUnclaimedDomain(c.Request.Context(), existing, userID)
			if err != nil {
				if errors.Is(err, errDomainClaimLost) {
					utils.RespondError(c, http.StatusConflict, "Domain already registered")
					return
				}
				if errors.Is(err, errDomainClaimCNAME) {
					utils.RespondError(c, http.StatusBadRequest, "To claim this domain, configure the CNAME record first: "+err.Error())
					return
				}
				utils.RespondError(c, http.StatusInternalServerError, "Failed to claim domain")
				return
			}
			utils.RespondSuccess(c, loadDomainDTO(domain))
			return
		}
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

	domain, err := createDomainRecord(userID, domainName)
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			utils.RespondError(c, http.StatusConflict, "Domain already registered")
			return
		}
		utils.RespondError(c, http.StatusInternalServerError, "Failed to create domain")
		return
	}

	utils.RespondSuccess(c, loadDomainDTO(domain))
}

// claimUnclaimedDomain transfers a pending domain to userID after live CNAME verification.
// The existing row (and its cname_target) is reused so claimers configure DNS using the
// target from a prior failed attempt or from GET /cname on the squatted name if exposed.
func claimUnclaimedDomain(ctx context.Context, existing models.Domain, userID uint) (models.Domain, error) {
	target := existing.CNameTarget
	if target == "" {
		target = config.DelegationTarget(existing.ID)
		if err := config.DB.Model(&existing).Update("cname_target", target).Error; err != nil {
			return models.Domain{}, err
		}
	}

	if err := services.VerifyChallengeCNAME(ctx, existing.Domain, target); err != nil {
		return models.Domain{}, fmt.Errorf("%w: point _acme-challenge.%s CNAME to %q (%v)",
			errDomainClaimCNAME, existing.Domain, target, err)
	}

	return assignUnclaimedDomainToUser(existing.ID, userID)
}

// assignUnclaimedDomainToUser atomically moves a claimable domain to a new owner.
func assignUnclaimedDomainToUser(domainID, userID uint) (models.Domain, error) {
	if domainHasCertificate(domainID) {
		return models.Domain{}, errDomainClaimLost
	}

	now := time.Now()
	result := config.DB.Model(&models.Domain{}).
		Where("id = ? AND status IN ?", domainID, []string{"pending", "error"}).
		Updates(map[string]interface{}{
			"user_id":                  userID,
			"status":                   "verified",
			"error_message":            "",
			"generating_since":         nil,
			"auto_renew":               true,
			"cname_verified_at":        now,
			"auto_renew_failures":      0,
			"auto_renew_backoff_until": nil,
		})
	if result.Error != nil {
		return models.Domain{}, result.Error
	}
	if result.RowsAffected == 0 {
		return models.Domain{}, errDomainClaimLost
	}

	var domain models.Domain
	if err := config.DB.First(&domain, domainID).Error; err != nil {
		return models.Domain{}, err
	}
	return domain, nil
}

func createDomainRecord(userID uint, domainName string) (models.Domain, error) {
	domain := models.Domain{
		UserID:    userID,
		Domain:    domainName,
		Status:    "pending",
		AutoRenew: true,
	}

	if err := config.DB.Create(&domain).Error; err != nil {
		return models.Domain{}, err
	}

	delegationTarget := config.DelegationTarget(domain.ID)
	if err := config.DB.Model(&domain).Update("cname_target", delegationTarget).Error; err != nil {
		config.DB.Delete(&domain)
		return models.Domain{}, err
	}
	domain.CNameTarget = delegationTarget
	return domain, nil
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

func UpdateDomain(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}

	var input UpdateDomainInput
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if input.AutoRenew == nil {
		utils.RespondError(c, http.StatusBadRequest, "autoRenew is required")
		return
	}

	updates := map[string]interface{}{
		"auto_renew": *input.AutoRenew,
	}
	if *input.AutoRenew {
		updates["auto_renew_failures"] = 0
		updates["auto_renew_backoff_until"] = nil
		updates["error_message"] = ""
	}

	if err := config.DB.Model(&domain).Updates(updates).Error; err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to update domain")
		return
	}
	if err := config.DB.First(&domain, domain.ID).Error; err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to load updated domain")
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
		"deleted_at":               nil,
		"status":                   "pending",
		"error_message":            "",
		"generating_since":         nil,
		"auto_renew":               true,
		"cname_verified_at":        nil,
		"auto_renew_failures":      0,
		"auto_renew_backoff_until": nil,
	}).Error
}

func permanentlyRemoveDomain(domainID uint) error {
	config.DB.Unscoped().Where("domain_id = ?", domainID).Delete(&models.Certificate{})
	config.DB.Unscoped().Where("domain_id = ?", domainID).Delete(&models.DeployTarget{})
	config.DB.Unscoped().Where("domain_id = ?", domainID).Delete(&models.DeployJob{})
	return config.DB.Unscoped().Delete(&models.Domain{}, domainID).Error
}

// isUnclaimedDomain reports whether another user may claim this domain after CNAME verification.
// Pending domains and error domains without certificates are eligible; error domains that had
// CNAME verified require unclaimed_error_release to elapse since the last status update.
func isUnclaimedDomain(domain models.Domain) bool {
	if domainHasCertificate(domain.ID) {
		return false
	}
	switch domain.Status {
	case "pending":
		return true
	case "error":
		if domain.CnameVerifiedAt == nil {
			return true
		}
		return time.Since(domain.UpdatedAt) >= config.Cfg.Domain.UnclaimedErrorReleaseDuration()
	default:
		return false
	}
}
