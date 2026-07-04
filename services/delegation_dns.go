package services

import (
	"context"
	"fmt"
	"log/slog"
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

func (c *cloudflareClient) createTXT(ctx context.Context, name, content string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
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
	rec, err := c.api.CreateDNSRecord(ctx, cf.ZoneIdentifier(zoneID), params)
	if err != nil {
		return "", fmt.Errorf("cloudflare create TXT: %w", err)
	}
	return rec.ID, nil
}

func (c *cloudflareClient) deleteTXT(ctx context.Context, recordID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	zoneID, err := c.getZoneID()
	if err != nil {
		return err
	}
	return c.api.DeleteDNSRecord(ctx, cf.ZoneIdentifier(zoneID), recordID)
}

// delegationTargetDNS serializes TXT records per delegation target so superseded ACME
// jobs cannot leave stale challenge records alongside a newer job.
type delegationTargetDNS struct {
	mu       sync.Mutex
	recordID string
}

var delegationTargetRecords sync.Map // delegation target host -> *delegationTargetDNS

func delegationTargetState(name string) *delegationTargetDNS {
	state, _ := delegationTargetRecords.LoadOrStore(name, &delegationTargetDNS{})
	return state.(*delegationTargetDNS)
}

func replaceDelegationTXT(ctx context.Context, client *cloudflareClient, targetName, content string) (string, error) {
	if err := requireACMEActive(ctx); err != nil {
		return "", err
	}

	state := delegationTargetState(targetName)
	state.mu.Lock()
	defer state.mu.Unlock()

	if err := requireACMEActive(ctx); err != nil {
		return "", err
	}

	if state.recordID != "" {
		if err := client.deleteTXT(ctx, state.recordID); err != nil {
			slog.Warn("cloudflare: failed to delete previous delegation TXT record",
				"target", targetName,
				"record_id", state.recordID,
				"error", err,
			)
		}
		state.recordID = ""
	}

	if err := requireACMEActive(ctx); err != nil {
		return "", err
	}

	recordID, err := client.createTXT(ctx, targetName, content)
	if err != nil {
		return "", err
	}
	state.recordID = recordID
	return recordID, nil
}

func releaseDelegationTXT(ctx context.Context, client *cloudflareClient, targetName, recordID string) error {
	state := delegationTargetState(targetName)
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.recordID != recordID {
		return nil
	}
	if err := client.deleteTXT(ctx, recordID); err != nil {
		return err
	}
	state.recordID = ""
	return nil
}

// DelegationDNSProvider creates TXT records on the auth zone at per-domain delegation targets.
type DelegationDNSProvider struct {
	ctx                 context.Context
	client              *cloudflareClient
	getDelegationTarget func(domain string) (string, error)
	recordIDs           map[string]string
	targetNames         map[string]string
	recordIDsMu         sync.Mutex
}

func newDelegationDNSProvider(ctx context.Context, getTarget func(domain string) (string, error)) (*DelegationDNSProvider, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	client, err := newCloudflareClient()
	if err != nil {
		return nil, err
	}
	return &DelegationDNSProvider{
		ctx:                 ctx,
		client:              client,
		getDelegationTarget: getTarget,
		recordIDs:           make(map[string]string),
		targetNames:         make(map[string]string),
	}, nil
}

func (d *DelegationDNSProvider) Present(domain, token, keyAuth string) error {
	if err := requireACMEActive(d.ctx); err != nil {
		return err
	}
	info := dns01.GetChallengeInfo(domain, keyAuth)

	delegationTarget, err := d.getDelegationTarget(domain)
	if err != nil {
		return fmt.Errorf("delegation DNS: lookup target for %q: %w", domain, err)
	}

	fqdn := dns01.ToFqdn(delegationTarget)
	name := dns01.UnFqdn(fqdn)

	recordID, err := replaceDelegationTXT(d.ctx, d.client, name, info.Value)
	if err != nil {
		return err
	}

	d.recordIDsMu.Lock()
	d.recordIDs[token] = recordID
	d.targetNames[token] = name
	d.recordIDsMu.Unlock()
	return nil
}

func (d *DelegationDNSProvider) CleanUp(domain, token, keyAuth string) error {
	d.recordIDsMu.Lock()
	recordID, ok := d.recordIDs[token]
	targetName := d.targetNames[token]
	if ok {
		delete(d.recordIDs, token)
		delete(d.targetNames, token)
	}
	d.recordIDsMu.Unlock()

	if !ok {
		slog.Debug("cloudflare: cleanup skipped, no TXT record tracked for token",
			"domain", domain,
			"token", token,
		)
		return nil
	}
	if err := releaseDelegationTXT(d.ctx, d.client, targetName, recordID); err != nil {
		slog.Warn("cloudflare: failed to delete TXT record",
			"domain", domain,
			"token", token,
			"record_id", recordID,
			"error", err,
		)
		return err
	}
	return nil
}

func (d *DelegationDNSProvider) Timeout() (timeout, interval time.Duration) {
	dns := config.Cfg.DNS
	return dns.PropagationTimeoutDuration(), dns.PropagationIntervalDuration()
}
