package services

import (
	"context"
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
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/utils"
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

func delegationTargetLookup(userID uint) func(domain string) (string, error) {
	return func(domainName string) (string, error) {
		domainName = utils.NormalizeDomain(domainName)
		var domain models.Domain
		if err := config.DB.Where("domain = ? AND user_id = ?", domainName, userID).First(&domain).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return "", fmt.Errorf("domain %q not found for user", domainName)
			}
			return "", err
		}
		if domain.CNameTarget == "" {
			return "", fmt.Errorf("domain %q has no delegation target configured", domainName)
		}
		return domain.CNameTarget, nil
	}
}

func loadOrCreateAcmeAccount(userID uint, email string) (*acmeUser, error) {
	user, err := loadAcmeAccount(userID)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	return createAcmeAccount(userID, email)
}

func loadAcmeAccount(userID uint) (*acmeUser, error) {
	var account models.AcmeAccount
	if err := config.DB.Where("user_id = ?", userID).First(&account).Error; err != nil {
		return nil, err
	}
	if err := invalidateRegistrationIfCAChanged(&account); err != nil {
		return nil, err
	}
	return acmeUserFromAccount(account)
}

func effectiveCAURL() string {
	if config.Cfg.ACME.CAURL != "" {
		return config.Cfg.ACME.CAURL
	}
	return lego.LEDirectoryProduction
}

func normalizeCAURL(url string) string {
	return strings.TrimSuffix(strings.TrimSpace(url), "/")
}

// invalidateRegistrationIfCAChanged clears a registration when acme.ca_url no longer matches.
func invalidateRegistrationIfCAChanged(account *models.AcmeAccount) error {
	stored := normalizeCAURL(account.CAURL)
	current := normalizeCAURL(effectiveCAURL())

	if stored == "" {
		if len(account.Registration) == 0 {
			return nil
		}
		// Legacy account: registration predates CA URL tracking; re-register against current CA.
		slog.Info("ACME legacy registration without CA URL, will re-register",
			"user_id", account.UserID,
			"current_ca", current,
		)
		account.Registration = nil
		return config.DB.Model(account).Update("registration", nil).Error
	}
	if stored == current {
		return nil
	}
	slog.Info("ACME CA URL changed, discarding stale registration",
		"user_id", account.UserID,
		"stored_ca", stored,
		"current_ca", current,
	)
	account.Registration = nil
	account.CAURL = ""
	return config.DB.Model(account).Updates(map[string]interface{}{
		"registration": nil,
		"ca_url":       "",
	}).Error
}

func acmeUserFromAccount(account models.AcmeAccount) (*acmeUser, error) {
	keyPEM, err := Decrypt(account.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("decrypt ACME account key: %w", err)
	}
	privateKey, err := parseECPrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}

	user := &acmeUser{
		Email: account.Email,
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
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return loadAcmeAccount(userID)
		}
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
		Updates(map[string]interface{}{
			"registration": data,
			"ca_url":       effectiveCAURL(),
		}).Error
}

func loadAcmeRegistration(userID uint) (*registration.Resource, error) {
	var account models.AcmeAccount
	if err := config.DB.Where("user_id = ?", userID).First(&account).Error; err != nil {
		return nil, err
	}
	if err := invalidateRegistrationIfCAChanged(&account); err != nil {
		return nil, err
	}
	if len(account.Registration) == 0 {
		return nil, nil
	}
	var reg registration.Resource
	if err := json.Unmarshal(account.Registration, &reg); err != nil {
		return nil, fmt.Errorf("parse ACME registration: %w", err)
	}
	return &reg, nil
}

func newLegoClient(ctx context.Context, user *acmeUser, userID uint) (*lego.Client, error) {
	cfg := lego.NewConfig(user)
	cfg.CADirURL = effectiveCAURL()
	cfg.Certificate.KeyType = certcrypto.RSA2048
	cfg.HTTPClient = acmeHTTPClient(ctx, cfg.HTTPClient)

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	provider, err := newDelegationDNSProvider(ctx, delegationTargetLookup(userID))
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, err
	}

	return client, nil
}

type acmeCertResult struct {
	certs *certificate.Resource
	err   error
}

// runACMEWithContext runs a blocking Lego Obtain/Renew call in a goroutine so the caller
// can return promptly when ctx is cancelled. Obtain/Renew have no context parameter, but
// the Lego HTTP client is bound to ctx and aborts in-flight CA requests on cancel.
// Lego's DNS-01 propagation poll loop is not context-aware and may continue for up to
// dns.propagation_timeout; callers must wait for the domain worker before reusing slots.
func runACMEWithContext(ctx context.Context, run func() (*certificate.Resource, error)) (*certificate.Resource, error) {
	if err := requireACMEActive(ctx); err != nil {
		return nil, err
	}
	ch := make(chan acmeCertResult, 1)
	go func() {
		if err := requireACMEActive(ctx); err != nil {
			select {
			case ch <- acmeCertResult{err: err}:
			case <-ctx.Done():
			}
			return
		}
		certs, err := run()
		select {
		case ch <- acmeCertResult{certs: certs, err: err}:
		case <-ctx.Done():
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := requireACMEActive(ctx); err != nil {
			return nil, err
		}
		return result.certs, result.err
	}
}

func obtainWithContext(ctx context.Context, client *lego.Client, request certificate.ObtainRequest) (*certificate.Resource, error) {
	return runACMEWithContext(ctx, func() (*certificate.Resource, error) {
		return client.Certificate.Obtain(request)
	})
}

func renewWithContext(ctx context.Context, client *lego.Client, existing certificate.Resource) (*certificate.Resource, error) {
	return runACMEWithContext(ctx, func() (*certificate.Resource, error) {
		return client.Certificate.Renew(existing, true, false, "")
	})
}

func ensureRegistered(ctx context.Context, client *lego.Client, user *acmeUser, userID uint) error {
	if err := requireACMEActive(ctx); err != nil {
		return err
	}
	if user.Registration != nil {
		return nil
	}
	if reg, err := loadAcmeRegistration(userID); err != nil {
		return err
	} else if reg != nil {
		user.Registration = reg
		return nil
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		if reg, dbErr := loadAcmeRegistration(userID); dbErr == nil && reg != nil {
			user.Registration = reg
			return nil
		}
		return fmt.Errorf("ACME registration: %w", err)
	}
	user.Registration = reg
	if err := saveAcmeRegistration(userID, reg); err != nil {
		if reg, dbErr := loadAcmeRegistration(userID); dbErr == nil && reg != nil {
			user.Registration = reg
			return nil
		}
		return fmt.Errorf("save ACME registration: %w", err)
	}
	slog.Info("registered new ACME account", "user_id", userID, "email", user.Email)
	return nil
}

// ObtainCertificate issues a new certificate for domain using DNS-01 CNAME delegation.
func ObtainCertificate(ctx context.Context, userID uint, domain string, email string) (*certificate.Resource, error) {
	if err := requireACMEActive(ctx); err != nil {
		return nil, err
	}

	user, err := loadOrCreateAcmeAccount(userID, email)
	if err != nil {
		return nil, err
	}

	client, err := newLegoClient(ctx, user, userID)
	if err != nil {
		return nil, err
	}

	if err := ensureRegistered(ctx, client, user, userID); err != nil {
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	return obtainWithContext(ctx, client, request)
}

// RenewExistingCertificate renews a certificate using the stored ACME account and cert resource.
func RenewExistingCertificate(ctx context.Context, userID uint, email string, existing *certificate.Resource) (*certificate.Resource, error) {
	if err := requireACMEActive(ctx); err != nil {
		return nil, err
	}

	user, err := loadOrCreateAcmeAccount(userID, email)
	if err != nil {
		return nil, err
	}

	client, err := newLegoClient(ctx, user, userID)
	if err != nil {
		return nil, err
	}

	if err := ensureRegistered(ctx, client, user, userID); err != nil {
		return nil, err
	}

	if existing.CertURL == "" {
		slog.Warn("cert URL missing, falling back to full obtain", "domain", existing.Domain)
		return ObtainCertificate(ctx, userID, existing.Domain, email)
	}

	renewed, err := renewWithContext(ctx, client, *existing)
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
