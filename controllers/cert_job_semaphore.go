package controllers

import (
	"sync"

	"github.com/hedwi/certhub-server/config"
)

var (
	certJobSlots     chan struct{}
	certJobSlotsOnce sync.Once
)

func certJobSlotsCh() chan struct{} {
	certJobSlotsOnce.Do(func() {
		n := config.Cfg.Renewal.MaxConcurrentCertJobs()
		certJobSlots = make(chan struct{}, n)
	})
	return certJobSlots
}

// tryAcquireCertJobSlot attempts to reserve a global cert job slot without blocking.
func tryAcquireCertJobSlot() bool {
	select {
	case certJobSlotsCh() <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseCertJobSlot() {
	select {
	case <-certJobSlotsCh():
	default:
	}
}
