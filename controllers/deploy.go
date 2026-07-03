package controllers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
)

type DeployTargetInput struct {
	Name          string `json:"name" binding:"required"`
	Type          string `json:"type" binding:"required"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Enabled       *bool  `json:"enabled"`
	AuthType      string `json:"authType"`
	User          string `json:"user"`
	PrivateKey    string `json:"privateKey"`
	Password      string `json:"password"`
	CertPath      string `json:"certPath"`
	ReloadCommand string `json:"reloadCommand"`
}

func ListDeployTargets(c *gin.Context) {
	if !requireDeployAPI(c) {
		return
	}
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}

	var targets []models.DeployTarget
	if err := config.DB.Where("domain_id = ?", domain.ID).Order("created_at asc").Find(&targets).Error; err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to list deploy targets")
		return
	}

	result := make([]DeployTargetDTO, 0, len(targets))
	for _, t := range targets {
		result = append(result, toDeployTargetDTO(t))
	}
	utils.RespondSuccess(c, result)
}

func AddDeployTarget(c *gin.Context) {
	if !requireDeployAPI(c) {
		return
	}
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}
	userID, ok := requireUserID(c)
	if !ok {
		return
	}

	var input DeployTargetInput
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	target := models.DeployTarget{
		DomainID:      domain.ID,
		UserID:        userID,
		Name:          input.Name,
		Type:          input.Type,
		Host:          input.Host,
		Port:          input.Port,
		Enabled:       true,
		AuthType:      input.AuthType,
		SSHUser:       input.User,
		CertPath:      input.CertPath,
		ReloadCommand: input.ReloadCommand,
	}
	if input.Enabled != nil {
		target.Enabled = *input.Enabled
	}
	if input.PrivateKey != "" {
		enc, err := services.Encrypt([]byte(input.PrivateKey))
		if err != nil {
			utils.RespondError(c, http.StatusInternalServerError, "Failed to encrypt private key")
			return
		}
		target.PrivateKeyPEM = enc
	}
	if input.Password != "" {
		enc, err := services.Encrypt([]byte(input.Password))
		if err != nil {
			utils.RespondError(c, http.StatusInternalServerError, "Failed to encrypt password")
			return
		}
		target.PasswordEnc = enc
	}

	if err := config.DB.Create(&target).Error; err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to create deploy target")
		return
	}
	utils.RespondSuccess(c, toDeployTargetDTO(target))
}

func UpdateDeployTarget(c *gin.Context) {
	if !requireDeployAPI(c) {
		return
	}
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}
	targetID, ok := parseDomainID(c.Param("targetId"))
	if !ok {
		utils.RespondError(c, http.StatusBadRequest, "Invalid target id")
		return
	}

	var target models.DeployTarget
	if err := config.DB.Where("id = ? AND domain_id = ?", targetID, domain.ID).First(&target).Error; err != nil {
		utils.RespondError(c, http.StatusNotFound, "Deploy target not found")
		return
	}

	var input DeployTargetInput
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	updates := map[string]interface{}{
		"name":           input.Name,
		"type":           input.Type,
		"host":           input.Host,
		"port":           input.Port,
		"auth_type":      input.AuthType,
		"ssh_user":       input.User,
		"cert_path":      input.CertPath,
		"reload_command": input.ReloadCommand,
	}
	if input.Enabled != nil {
		updates["enabled"] = *input.Enabled
	}
	if input.PrivateKey != "" {
		enc, err := services.Encrypt([]byte(input.PrivateKey))
		if err != nil {
			utils.RespondError(c, http.StatusInternalServerError, "Failed to encrypt private key")
			return
		}
		updates["private_key_pem"] = enc
	}
	if input.Password != "" {
		enc, err := services.Encrypt([]byte(input.Password))
		if err != nil {
			utils.RespondError(c, http.StatusInternalServerError, "Failed to encrypt password")
			return
		}
		updates["password_enc"] = enc
	}
	config.DB.Model(&target).Updates(updates)
	config.DB.Where("id = ?", target.ID).First(&target)
	utils.RespondSuccess(c, toDeployTargetDTO(target))
}

func DeleteDeployTarget(c *gin.Context) {
	if !requireDeployAPI(c) {
		return
	}
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}
	targetID, ok := parseDomainID(c.Param("targetId"))
	if !ok {
		utils.RespondError(c, http.StatusBadRequest, "Invalid target id")
		return
	}

	result := config.DB.Where("id = ? AND domain_id = ?", targetID, domain.ID).Delete(&models.DeployTarget{})
	if result.Error != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to delete deploy target")
		return
	}
	if result.RowsAffected == 0 {
		utils.RespondError(c, http.StatusNotFound, "Deploy target not found")
		return
	}
	utils.RespondSuccess(c, nil)
}

func DeployDomain(c *gin.Context) {
	if !requireDeployExecution(c) {
		return
	}
}

func GetDeployJob(c *gin.Context) {
	if !requireDeployAPI(c) {
		return
	}
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}
	jobID, ok := parseDomainID(c.Param("jobId"))
	if !ok {
		utils.RespondError(c, http.StatusBadRequest, "Invalid job id")
		return
	}

	var job models.DeployJob
	if err := config.DB.Where("id = ? AND domain_id = ?", jobID, domain.ID).First(&job).Error; err != nil {
		utils.RespondError(c, http.StatusNotFound, "Deploy job not found")
		return
	}
	utils.RespondSuccess(c, toDeployJobDTO(job))
}

func toDeployJobDTO(job models.DeployJob) DeployJobDTO {
	dto := DeployJobDTO{
		ID:        strconv.FormatUint(uint64(job.ID), 10),
		Status:    job.Status,
		CreatedAt: formatTime(job.CreatedAt),
	}
	dto.FinishedAt = formatTimePtr(job.FinishedAt)
	if len(job.TargetsJSON) > 0 {
		var targets []DeployJobTargetDTO
		if err := json.Unmarshal(job.TargetsJSON, &targets); err == nil {
			dto.Targets = targets
		}
	}
	return dto
}
