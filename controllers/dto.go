package controllers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/hedwi/certhub-server/models"
)

type DomainDTO struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Status        string  `json:"status"`
	CertStatus    string  `json:"certStatus"`
	CertExpiresAt *string `json:"certExpiresAt,omitempty"`
	AutoRenew     bool    `json:"autoRenew"`
	RenewError    *string `json:"renewError,omitempty"`
	CreatedAt     string  `json:"createdAt"`
}

type CnameRecordDTO struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Verified bool   `json:"verified"`
}

type CnameConfigDTO struct {
	DomainID     string           `json:"domainId"`
	Records      []CnameRecordDTO `json:"records"`
	Instructions string           `json:"instructions,omitempty"`
	Note         string           `json:"note,omitempty"`
	Verified     bool             `json:"verified,omitempty"`
	VerifiedAt   *string          `json:"verifiedAt,omitempty"`
	LiveChecked  bool             `json:"liveChecked"`
}

type CertificateInfoDTO struct {
	DomainID     string  `json:"domainId"`
	Status       string  `json:"status"`
	ExpiresAt    *string `json:"expiresAt,omitempty"`
	Issuer       string  `json:"issuer,omitempty"`
	SerialNumber string  `json:"serialNumber,omitempty"`
}

type CertificateDownloadDTO struct {
	Certificate string `json:"certificate,omitempty"`
	PrivateKey  string `json:"privateKey,omitempty"`
	Chain       string `json:"chain,omitempty"`
	Fullchain   string `json:"fullchain,omitempty"`
}

type DeployTargetDTO struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	Host         string  `json:"host,omitempty"`
	Port         *int    `json:"port,omitempty"`
	Enabled      bool    `json:"enabled"`
	LastDeployAt *string `json:"lastDeployAt,omitempty"`
	LastStatus   string  `json:"lastStatus,omitempty"`
}

type DeployJobTargetDTO struct {
	TargetID   string `json:"targetId"`
	TargetName string `json:"targetName"`
	Status     string `json:"status"`
	Message    string `json:"message,omitempty"`
}

type DeployJobDTO struct {
	ID         string               `json:"id"`
	Status     string               `json:"status"`
	Targets    []DeployJobTargetDTO `json:"targets,omitempty"`
	CreatedAt  string               `json:"createdAt,omitempty"`
	FinishedAt *string              `json:"finishedAt,omitempty"`
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := formatTime(*t)
	return &s
}

func mapDomainStatus(status string) string {
	switch status {
	case "active":
		return "active"
	case "error":
		return "failed"
	case "generating":
		return "generating"
	case "verified":
		return "verified"
	default:
		return "pending"
	}
}

func mapCertStatus(domain models.Domain, cert *models.Certificate) string {
	switch domain.Status {
	case "error":
		return "failed"
	case "generating":
		return "generating"
	}
	if cert == nil {
		return "none"
	}
	if time.Now().After(cert.ExpiresAt) {
		return "expired"
	}
	if domain.Status == "active" {
		return "valid"
	}
	return "pending"
}

func toDomainDTO(domain models.Domain, cert *models.Certificate) DomainDTO {
	dto := DomainDTO{
		ID:         strconv.FormatUint(uint64(domain.ID), 10),
		Name:       domain.Domain,
		Status:     mapDomainStatus(domain.Status),
		CertStatus: mapCertStatus(domain, cert),
		AutoRenew:  domain.AutoRenew,
		CreatedAt:  formatTime(domain.CreatedAt),
	}
	if cert != nil && !cert.ExpiresAt.IsZero() {
		exp := formatTime(cert.ExpiresAt)
		dto.CertExpiresAt = &exp
	}
	if domain.ErrorMessage != "" && domain.Status == "active" {
		msg := domain.ErrorMessage
		dto.RenewError = &msg
	}
	return dto
}

func isCnameVerifiedStatus(status string) bool {
	switch status {
	case "verified", "active", "generating":
		return true
	default:
		return false
	}
}

func toCnameConfigDTO(domain models.Domain, liveVerified *bool) CnameConfigDTO {
	cnameHost := "_acme-challenge." + domain.Domain

	verified := false
	liveChecked := false
	switch {
	case liveVerified != nil:
		verified = *liveVerified
		liveChecked = true
	case domain.CNameTarget != "":
		verified = isCnameVerifiedStatus(domain.Status)
	}

	return CnameConfigDTO{
		DomainID: strconv.FormatUint(uint64(domain.ID), 10),
		Records: []CnameRecordDTO{{
			Type:     "CNAME",
			Name:     cnameHost,
			Value:    domain.CNameTarget,
			Verified: verified,
		}},
		Instructions: fmt.Sprintf("Add a CNAME record at your DNS host: %s → %s", cnameHost, domain.CNameTarget),
		Note: "CNAME delegation: add the record above at any DNS provider. ACME challenge TXT records are published automatically on the delegation target; no DNS API credentials are required from you.",
		Verified:     verified,
		VerifiedAt:   formatTimePtr(domain.CnameVerifiedAt),
		LiveChecked:  liveChecked,
	}
}

func toCertificateInfoDTO(domain models.Domain, cert *models.Certificate) CertificateInfoDTO {
	dto := CertificateInfoDTO{
		DomainID: strconv.FormatUint(uint64(domain.ID), 10),
		Status:   mapCertStatus(domain, cert),
	}
	if cert == nil {
		return dto
	}
	if !cert.ExpiresAt.IsZero() {
		exp := formatTime(cert.ExpiresAt)
		dto.ExpiresAt = &exp
	}
	if issuer, serial := parseCertMeta(cert.CertPEM); issuer != "" || serial != "" {
		dto.Issuer = issuer
		dto.SerialNumber = serial
	}
	return dto
}

func toCertificateDownloadDTO(cert *models.Certificate, keyPEM []byte) CertificateDownloadDTO {
	certStr := string(cert.CertPEM)
	chainStr := string(cert.Issuer)
	return CertificateDownloadDTO{
		Certificate: certStr,
		PrivateKey:  string(keyPEM),
		Chain:       chainStr,
		Fullchain:   certStr + "\n" + chainStr,
	}
}

func toDeployTargetDTO(t models.DeployTarget) DeployTargetDTO {
	dto := DeployTargetDTO{
		ID:         strconv.FormatUint(uint64(t.ID), 10),
		Name:       t.Name,
		Type:       t.Type,
		Host:       t.Host,
		Enabled:    t.Enabled,
		LastStatus: t.LastStatus,
	}
	if t.Port > 0 {
		p := t.Port
		dto.Port = &p
	}
	dto.LastDeployAt = formatTimePtr(t.LastDeployAt)
	return dto
}

func parseCertMeta(certPEM []byte) (issuer, serial string) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", ""
	}
	issuer = cert.Issuer.CommonName
	if issuer == "" && len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}
	serial = formatSerial(cert.SerialNumber)
	return issuer, serial
}

func formatSerial(n *big.Int) string {
	if n == nil {
		return ""
	}
	return fmt.Sprintf("%X", n)
}
