package services

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	cf "github.com/cloudflare/cloudflare-go"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/hedwi/certhub-server/config"
)

const cloudflareMinTTL = 120

// cloudflareClient wraps the public cloudflare-go API for DNS record management.
type cloudflareClient struct {
	api      *cf.API
	authZone string
	zoneID   string
	zoneOnce sync.Once
	zoneErr  error
}

func newCloudflareClient() (*cloudflareClient, error) {
	cfCfg := config.Cfg.DNS.Cloudflare
	var api *cf.API
	var err error
	if cfCfg.APIToken != "" {
		api, err = cf.NewWithAPIToken(cfCfg.APIToken, cf.HTTPClient(&http.Client{Timeout: 30 * time.Second}))
	} else {
		api, err = cf.New(cfCfg.APIKey, cfCfg.APIEmail, cf.HTTPClient(&http.Client{Timeout: 30 * time.Second}))
	}
	if err != nil {
		return nil, fmt.Errorf("cloudflare client: %w", err)
	}
	return &cloudflareClient{
		api:      api,
		authZone: config.Cfg.DNS.AuthZone,
	}, nil
}

func (c *cloudflareClient) getZoneID() (string, error) {
	c.zoneOnce.Do(func() {
		c.zoneID, c.zoneErr = c.api.ZoneIDByName(c.authZone)
	})
	return c.zoneID, c.zoneErr
}

func (c *cloudflareClient) createTXT(name, content string) (string, error) {
	zoneID, err := c.getZoneID()
	if err != nil {
		return "", fmt.Errorf("cloudflare zone lookup: %w", err)
	}
	params := cf.CreateDNSRecordParams{
		Type:    "TXT",
		Name:    name,
		Content: content,
		TTL:     cloudflareMinTTL,
	}
	rec, err := c.api.CreateDNSRecord(context.Background(), cf.ZoneIdentifier(zoneID), params)
	if err != nil {
		return "", fmt.Errorf("cloudflare create TXT: %w", err)
	}
	return rec.ID, nil
}

func (c *cloudflareClient) deleteTXT(recordID string) error {
	zoneID, err := c.getZoneID()
	if err != nil {
		return err
	}
	return c.api.DeleteDNSRecord(context.Background(), cf.ZoneIdentifier(zoneID), recordID)
}

// DelegationDNSProvider creates TXT records on the auth zone at per-domain delegation targets.
type DelegationDNSProvider struct {
	client              *cloudflareClient
	getDelegationTarget func(domain string) (string, error)
	recordIDs           map[string]string
	recordIDsMu         sync.Mutex
}

func newDelegationDNSProvider(getTarget func(domain string) (string, error)) (*DelegationDNSProvider, error) {
	client, err := newCloudflareClient()
	if err != nil {
		return nil, err
	}
	return &DelegationDNSProvider{
		client:              client,
		getDelegationTarget: getTarget,
		recordIDs:           make(map[string]string),
	}, nil
}

func (d *DelegationDNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	delegationTarget, err := d.getDelegationTarget(domain)
	if err != nil {
		return fmt.Errorf("delegation DNS: lookup target for %q: %w", domain, err)
	}

	fqdn := dns01.ToFqdn(delegationTarget)
	name := dns01.UnFqdn(fqdn)

	recordID, err := d.client.createTXT(name, info.Value)
	if err != nil {
		return err
	}

	d.recordIDsMu.Lock()
	d.recordIDs[token] = recordID
	d.recordIDsMu.Unlock()
	return nil
}

func (d *DelegationDNSProvider) CleanUp(domain, token, keyAuth string) error {
	d.recordIDsMu.Lock()
	recordID, ok := d.recordIDs[token]
	if ok {
		delete(d.recordIDs, token)
	}
	d.recordIDsMu.Unlock()

	if !ok {
		return nil
	}
	return d.client.deleteTXT(recordID)
}

func (d *DelegationDNSProvider) Timeout() (timeout, interval time.Duration) {
	return 2 * time.Minute, 2 * time.Second
}
