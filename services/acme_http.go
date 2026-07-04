package services

import (
	"context"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/lego"
	"github.com/hedwi/certhub-server/config"
)

// acmeHTTPClient returns an HTTP client whose requests are bound to ctx.
// Lego does not accept context on Obtain/Renew, but all ACME HTTP traffic uses
// Config.HTTPClient, so cancellation aborts in-flight CA requests promptly.
func acmeHTTPClient(ctx context.Context, base *http.Client) *http.Client {
	if base == nil {
		base = lego.NewConfig(nil).HTTPClient
	}
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{
		Timeout:       base.Timeout,
		Transport:     &contextRoundTripper{ctx: ctx, base: transport},
		CheckRedirect: base.CheckRedirect,
		Jar:           base.Jar,
	}
}

type contextRoundTripper struct {
	ctx  context.Context
	base http.RoundTripper
}

func (t *contextRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req.WithContext(t.ctx))
}

// acmeLegoHTTPRoundBudget is the per-request timeout Lego sets on its default client.
const acmeLegoHTTPRoundBudget = 2 * time.Minute

// ACMEWorkDrainBudget returns how long shutdown should wait for in-flight Lego work
// after cancellation. DNS-01 propagation polling inside Lego is not context-aware and
// may run up to the configured propagation timeout; add HTTP round-trip headroom.
func ACMEWorkDrainBudget() time.Duration {
	propagation := config.Cfg.DNS.PropagationTimeoutDuration()
	budget := propagation + acmeLegoHTTPRoundBudget + 30*time.Second
	if max := config.Cfg.Renewal.GeneratingTimeoutDuration(); budget > max {
		return max
	}
	return budget
}
