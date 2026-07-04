package services

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hedwi/certhub-server/config"
)

func TestContextRoundTripper_CancelsInFlightRequest(t *testing.T) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	client := acmeHTTPClient(ctx, &http.Client{Transport: http.DefaultTransport})

	done := make(chan error, 1)
	go func() {
		_, err := client.Get(server.URL)
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancelled request to fail")
		}
	case <-time.After(time.Second):
		t.Fatal("request did not return after context cancel")
	}
}

func TestContextRoundTripper_RejectsAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := acmeHTTPClient(ctx, &http.Client{Transport: http.DefaultTransport})
	_, err := client.Get("http://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestACMEWorkDrainBudget(t *testing.T) {
	saved := config.Cfg
	t.Cleanup(func() { config.Cfg = saved })

	config.Cfg.DNS.PropagationTimeout = "5m"
	config.Cfg.Renewal.GeneratingTimeout = "15m"
	want := 5*time.Minute + acmeLegoHTTPRoundBudget + 30*time.Second
	if got := ACMEWorkDrainBudget(); got != want {
		t.Fatalf("budget=%v, want %v", got, want)
	}

	config.Cfg.DNS.PropagationTimeout = "20m"
	config.Cfg.Renewal.GeneratingTimeout = "15m"
	if got := ACMEWorkDrainBudget(); got != 15*time.Minute {
		t.Fatalf("budget=%v, want capped at generating timeout 15m", got)
	}
}

func TestAcmeHTTPClientPreservesLegoDefaults(t *testing.T) {
	base := acmeHTTPClient(context.Background(), nil)
	if base.Timeout != 2*time.Minute {
		t.Fatalf("timeout=%v, want lego default 2m", base.Timeout)
	}
	if base.Transport == nil {
		t.Fatal("expected transport")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := acmeHTTPClient(ctx, base)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(server.Close)

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
}
