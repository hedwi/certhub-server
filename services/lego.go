package services

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
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

	config := lego.NewConfig(myUser)

	// Default to Let's Encrypt production. Override via env for testing.
	config.CADirURL = os.Getenv("ACME_CA_URL")
	if config.CADirURL == "" {
		config.CADirURL = lego.LEDirectoryProduction
	}
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
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
	// The CNAME setup works automatically with Lego if the provider follows CNAMEs.
	// We'll configure our main provider (e.g. Cloudflare) to answer the challenge
	// for the domain the CNAME points to.

	providerName := os.Getenv("DNS_PROVIDER") // e.g. "cloudflare"

	if providerName == "cloudflare" {
		config := cloudflare.NewDefaultConfig()
		// Will automatically read CF_API_EMAIL(or CLOUDFLARE_EMAIL) and CF_API_KEY from env

		p, err := cloudflare.NewDNSProviderConfig(config)
		if err != nil {
			return err
		}

		err = client.Challenge.SetDNS01Provider(p)
		return err
	}

	return errors.New("Unsupported or missing DNS_PROVIDER config (e.g., 'cloudflare')")
}
