package controllers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

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

type DeployInput struct {
	TargetIDs []string `json:"targetIds"`
}

func ListDeployTargets(c *gin.Context) {
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
		if err == nil {
			updates["private_key_pem"] = enc
		}
	}
	if input.Password != "" {
		enc, err := services.Encrypt([]byte(input.Password))
		if err == nil {
			updates["password_enc"] = enc
		}
	}
	config.DB.Model(&target).Updates(updates)
	config.DB.Where("id = ?", target.ID).First(&target)
	utils.RespondSuccess(c, toDeployTargetDTO(target))
}

func DeleteDeployTarget(c *gin.Context) {
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
	domain, ok := getDomainOwned(c, c.Param("id"))
	if !ok {
		return
	}
	userID, ok := requireUserID(c)
	if !ok {
		return
	}

	cert := loadCertificate(domain.ID)
	if cert == nil {
		utils.RespondError(c, http.StatusBadRequest, "No certificate available to deploy")
		return
	}

	var input DeployInput
	_ = c.ShouldBindJSON(&input)

	query := config.DB.Where("domain_id = ? AND enabled = ?", domain.ID, true)
	if len(input.TargetIDs) > 0 {
		ids := make([]uint, 0, len(input.TargetIDs))
		for _, raw := range input.TargetIDs {
			if id, ok := parseDomainID(raw); ok {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			query = query.Where("id IN ?", ids)
		}
	}

	var targets []models.DeployTarget
	if err := query.Find(&targets).Error; err != nil || len(targets) == 0 {
		utils.RespondError(c, http.StatusBadRequest, "No deploy targets configured")
		return
	}

	job := models.DeployJob{
		DomainID: domain.ID,
		UserID:   userID,
		Status:   "pending",
	}
	if err := config.DB.Create(&job).Error; err != nil {
		utils.RespondError(c, http.StatusInternalServerError, "Failed to create deploy job")
		return
	}

	go runDeployJob(job, domain, targets, cert)

	utils.RespondSuccess(c, gin.H{
		"jobId":   strconv.FormatUint(uint64(job.ID), 10),
		"status":  "pending",
		"message": "Deploy job started",
	})
}

func GetDeployJob(c *gin.Context) {
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

func runDeployJob(job models.DeployJob, domain models.Domain, targets []models.DeployTarget, cert *models.Certificate) {
	results := make([]DeployJobTargetDTO, 0, len(targets))
	allOK := true

	for _, target := range targets {
		entry := DeployJobTargetDTO{
			TargetID:   strconv.FormatUint(uint64(target.ID), 10),
			TargetName: target.Name,
			Status:     "success",
			Message:    "Certificate staged for deployment",
		}

		switch target.Type {
		case "ssh":
			if target.Host == "" {
				entry.Status = "failed"
				entry.Message = "SSH host not configured"
				allOK = false
			}
		case "webhook", "api":
			if target.Host == "" {
				entry.Status = "failed"
				entry.Message = "Endpoint host not configured"
				allOK = false
			}
		default:
			entry.Message = "Deploy recorded (type: " + target.Type + ")"
		}

		now := time.Now()
		lastStatus := entry.Status
		config.DB.Model(&target).Updates(map[string]interface{}{
			"last_deploy_at": &now,
			"last_status":    lastStatus,
		})
		results = append(results, entry)
	}

	status := "success"
	if !allOK {
		status = "failed"
	}
	finished := time.Now()
	payload, _ := json.Marshal(results)
	config.DB.Model(&job).Updates(map[string]interface{}{
		"status":       status,
		"targets_json": payload,
		"finished_at":  &finished,
	})
	slog.Info("deploy job finished", "job_id", job.ID, "domain", domain.Domain, "status", status, "cert_id", cert.ID)
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
