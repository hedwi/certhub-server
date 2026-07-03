package controllers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
)

type IssueCertInput struct {
	ForceRenew bool `json:"forceRenew"`
}

func issueCertificateInternal(c *gin.Context, domainID uint, forceRenew bool) {
	userID, ok := requireUserID(c)
	if !ok {
		return
	}

	var domain models.Domain
	if err := config.DB.Where("id = ? AND user_id = ?", domainID, userID).First(&domain).Error; err != nil {
		utils.RespondError(c, http.StatusNotFound, "Domain not found")
		return
	}

	user, ok := beginCertOperation(c, domain, userID, forceRenew)
	if !ok {
		return
	}

	go runCertJob(domain, *user, forceRenew)

	utils.RespondSuccess(c, gin.H{
		"status":  "pending",
		"message": "Certificate issuance started. Refresh the domain to check status.",
	})
}

func IssueCertificate(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}

	var input IssueCertInput
	_ = c.ShouldBindJSON(&input)

	issueCertificateInternal(c, domain.ID, input.ForceRenew)
}

func GenerateCertificate(c *gin.Context) {
	var input struct {
		DomainID uint `json:"domain_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}
	issueCertificateInternal(c, input.DomainID, false)
}

func RenewCertificate(c *gin.Context) {
	var input struct {
		DomainID uint `json:"domain_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}
	issueCertificateInternal(c, input.DomainID, true)
}

func GetCertificateInfo(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}
	cert := loadCertificate(domain.ID)
	utils.RespondSuccess(c, toCertificateInfoDTO(domain, cert))
}

func DownloadDomainCertificate(c *gin.Context) {
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}

	cert := loadCertificate(domain.ID)
	if cert == nil {
		utils.RespondError(c, http.StatusNotFound, "Certificate not found")
		return
	}

	keyPEM, err := services.Decrypt(cert.KeyPEM)
	if err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to decrypt private key")
		return
	}

	format := c.DefaultQuery("format", "pem")
	if format == "zip" {
		writeCertificateZip(c, domain.Domain, cert, keyPEM)
		return
	}

	utils.RespondSuccess(c, toCertificateDownloadDTO(cert, keyPEM))
}

func ListCertificates(c *gin.Context) {
	userID, ok := requireUserID(c)
	if !ok {
		return
	}

	var domains []models.Domain
	if err := config.DB.Where("user_id = ?", userID).Find(&domains).Error; err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to fetch certificates")
		return
	}

	result := make([]CertificateInfoDTO, 0)
	for _, d := range domains {
		cert := loadCertificate(d.ID)
		if cert != nil {
			result = append(result, toCertificateInfoDTO(d, cert))
		}
	}
	utils.RespondSuccess(c, result)
}

func DownloadCertificate(c *gin.Context) {
	certID := c.Param("id")
	userID, ok := requireUserID(c)
	if !ok {
		return
	}

	var cert models.Certificate
	if err := config.DB.Where("id = ? AND user_id = ?", certID, userID).First(&cert).Error; err != nil {
		utils.RespondError(c, http.StatusNotFound, "Certificate not found")
		return
	}

	c.Params = gin.Params{{Key: "id", Value: strconv.FormatUint(uint64(cert.DomainID), 10)}}
	DownloadDomainCertificate(c)
}
