package services

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"gorm.io/gorm"
)

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func lookupDelegationTarget(domainName string) (string, error) {
	var domain models.Domain
	if err := config.DB.Where("domain = ?", domainName).First(&domain).Error; err != nil {
		return "", err
	}
	if domain.CNameTarget == "" {
		return "", fmt.Errorf("domain %q has no delegation target configured", domainName)
	}
	return domain.CNameTarget, nil
}

func loadOrCreateAcmeAccount(userID uint, email string) (*acmeUser, error) {
	var account models.AcmeAccount
	err := config.DB.Where("user_id = ?", userID).First(&account).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return createAcmeAccount(userID, email)
	}

	keyPEM, err := Decrypt(account.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("decrypt ACME account key: %w", err)
	}
	privateKey, err := parseECPrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}

	user := &acmeUser{
		Email: email,
		key:   privateKey,
	}

	if len(account.Registration) > 0 {
		var reg registration.Resource
		if err := json.Unmarshal(account.Registration, &reg); err != nil {
			return nil, fmt.Errorf("parse ACME registration: %w", err)
		}
		user.Registration = &reg
	}

	return user, nil
}

func createAcmeAccount(userID uint, email string) (*acmeUser, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyPEM, err := encodeECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	encryptedKey, err := Encrypt(keyPEM)
	if err != nil {
		return nil, err
	}

	account := models.AcmeAccount{
		UserID:        userID,
		Email:         email,
		PrivateKeyPEM: encryptedKey,
	}
	if err := config.DB.Create(&account).Error; err != nil {
		return nil, err
	}

	return &acmeUser{
		Email: email,
		key:   privateKey,
	}, nil
}

func saveAcmeRegistration(userID uint, reg *registration.Resource) error {
	data, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	return config.DB.Model(&models.AcmeAccount{}).
		Where("user_id = ?", userID).
		Update("registration", data).Error
}

func newLegoClient(user *acmeUser) (*lego.Client, error) {
	cfg := lego.NewConfig(user)
	cfg.CADirURL = config.Cfg.ACME.CAURL
	if cfg.CADirURL == "" {
		cfg.CADirURL = lego.LEDirectoryProduction
	}
	cfg.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	provider, err := newDelegationDNSProvider(lookupDelegationTarget)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, err
	}

	return client, nil
}

func ensureRegistered(client *lego.Client, user *acmeUser, userID uint) error {
	if user.Registration != nil {
		return nil
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("ACME registration: %w", err)
	}
	user.Registration = reg
	if err := saveAcmeRegistration(userID, reg); err != nil {
		return fmt.Errorf("save ACME registration: %w", err)
	}
	slog.Info("registered new ACME account", "user_id", userID, "email", user.Email)
	return nil
}

// ObtainCertificate issues a new certificate for domain using DNS-01 CNAME delegation.
func ObtainCertificate(userID uint, domain string, email string) (*certificate.Resource, error) {
	user, err := loadOrCreateAcmeAccount(userID, email)
	if err != nil {
		return nil, err
	}

	client, err := newLegoClient(user)
	if err != nil {
		return nil, err
	}

	if err := ensureRegistered(client, user, userID); err != nil {
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// RenewExistingCertificate renews a certificate using the stored ACME account and cert resource.
func RenewExistingCertificate(userID uint, email string, existing *certificate.Resource) (*certificate.Resource, error) {
	user, err := loadOrCreateAcmeAccount(userID, email)
	if err != nil {
		return nil, err
	}

	client, err := newLegoClient(user)
	if err != nil {
		return nil, err
	}

	if err := ensureRegistered(client, user, userID); err != nil {
		return nil, err
	}

	if existing.CertURL == "" {
		slog.Warn("cert URL missing, falling back to full obtain", "domain", existing.Domain)
		return ObtainCertificate(userID, existing.Domain, email)
	}

	renewed, err := client.Certificate.Renew(*existing, true, false, "")
	if err != nil {
		return nil, fmt.Errorf("ACME renew: %w", err)
	}
	return renewed, nil
}

// BuildCertResource reconstructs a lego certificate.Resource from DB model fields.
func BuildCertResource(cert *models.Certificate) (*certificate.Resource, error) {
	keyPEM, err := Decrypt(cert.KeyPEM)
	if err != nil {
		return nil, err
	}
	return &certificate.Resource{
		Domain:            cert.Domain,
		CertURL:           cert.CertURL,
		CertStableURL:     cert.CertStableURL,
		Certificate:       cert.CertPEM,
		PrivateKey:        keyPEM,
		IssuerCertificate: cert.Issuer,
	}, nil
}

func encodeECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func parseECPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode EC private key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
