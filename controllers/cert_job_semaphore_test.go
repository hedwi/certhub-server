package controllers

import (
	"sync"
	"testing"

	"github.com/hedwi/certhub-server/config"
)

func initCertJobSlotsForTest(n int) {
	certJobSlots = make(chan struct{}, n)
	certJobSlotsOnce = sync.Once{}
	certJobSlotsOnce.Do(func() {})
}

func TestTryAcquireCertJobSlot(t *testing.T) {
	saved := config.Cfg
	t.Cleanup(func() {
		config.Cfg = saved
		certJobSlots = nil
		certJobSlotsOnce = sync.Once{}
	})

	config.Cfg.Renewal.MaxConcurrentJobs = 2
	initCertJobSlotsForTest(2)

	if !tryAcquireCertJobSlot() || !tryAcquireCertJobSlot() {
		t.Fatal("expected first two slot acquires to succeed")
	}
	if tryAcquireCertJobSlot() {
		t.Fatal("expected third acquire to fail when at capacity")
	}

	releaseCertJobSlot()
	if !tryAcquireCertJobSlot() {
		t.Fatal("expected acquire to succeed after release")
	}
}
