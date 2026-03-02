package services

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hedwi/certhub-server/config"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func ObtainCertificate(domain string, email string) (*certificate.Resource, error) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	myUser := &MyUser{
		Email: email,
		key:   privateKey,
	}

	legoCfg := lego.NewConfig(myUser)
	legoCfg.CADirURL = config.Cfg.ACME.CAURL
	if legoCfg.CADirURL == "" {
		legoCfg.CADirURL = lego.LEDirectoryProduction
	}
	legoCfg.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, err
	}

	// Setup DNS Provider
	err = setupDNSProvider(client)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	return certificates, nil
}

func setupDNSProvider(client *lego.Client) error {
	providerName := config.Cfg.DNS.Provider
	if providerName == "" {
		providerName = "cloudflare"
	}

	if providerName == "cloudflare" {
		cf := config.Cfg.DNS.Cloudflare
		cfCfg := &cloudflare.Config{}
		if cf.APIToken != "" {
			cfCfg.AuthToken = cf.APIToken
		} else {
			cfCfg.AuthEmail = cf.APIEmail
			cfCfg.AuthKey = cf.APIKey
		}

		p, err := cloudflare.NewDNSProviderConfig(cfCfg)
		if err != nil {
			return err
		}

		return client.Challenge.SetDNS01Provider(p)
	}

	return errors.New("Unsupported or missing DNS_PROVIDER config (e.g., 'cloudflare')")
}
