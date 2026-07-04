package controllers

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hedwi/certhub-server/config"
)

type certJobEntry struct {
	token  uint64
	ctx    context.Context
	cancel context.CancelFunc
}

type certJobRegistry struct {
	mu   sync.Mutex
	jobs map[uint]*certJobEntry
}

type domainWorkerTracker struct {
	wg sync.WaitGroup
}

var (
	certJobs         = certJobRegistry{jobs: make(map[uint]*certJobEntry)}
	certJobTokenSeq  uint64
	domainWorkerByID sync.Map // domain ID -> *domainWorkerTracker
)

func domainWorkerTrackerFor(domainID uint) *domainWorkerTracker {
	tracker, _ := domainWorkerByID.LoadOrStore(domainID, &domainWorkerTracker{})
	return tracker.(*domainWorkerTracker)
}

// beginDomainWorker marks the start of a certificate job goroutine for domainID.
// The returned function must run when the goroutine exits (typically via defer).
func beginDomainWorker(domainID uint) func() {
	tracker := domainWorkerTrackerFor(domainID)
	tracker.wg.Add(1)
	return func() {
		tracker.wg.Done()
	}
}

// waitDomainWorker blocks until the in-flight worker goroutine for domainID finishes.
func waitDomainWorker(domainID uint, timeout time.Duration) bool {
	tracker, ok := domainWorkerByID.Load(domainID)
	if !ok {
		return true
	}
	done := make(chan struct{})
	go func() {
		tracker.(*domainWorkerTracker).wg.Wait()
		close(done)
	}()
	if timeout <= 0 {
		<-done
		return true
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// beginCertJob registers an in-flight job for domainID and returns its context, token, and a release func.
// When superseding a prior job, the prior context is cancelled and this call waits for its worker to exit
// before registering the replacement (so semaphore slots and DNS hooks are not overlapped).
func beginCertJob(domainID uint) (context.Context, uint64, func()) {
	certJobs.mu.Lock()
	if existing, ok := certJobs.jobs[domainID]; ok {
		existing.cancel()
	}
	certJobs.mu.Unlock()

	waitDomainWorker(domainID, config.Cfg.Renewal.GeneratingTimeoutDuration())

	certJobs.mu.Lock()
	defer certJobs.mu.Unlock()

	timeout := config.Cfg.Renewal.GeneratingTimeoutDuration()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	token := atomic.AddUint64(&certJobTokenSeq, 1)
	certJobs.jobs[domainID] = &certJobEntry{token: token, ctx: ctx, cancel: cancel}

	release := func() {
		certJobs.endJob(domainID, token)
	}
	return ctx, token, release
}

func (r *certJobRegistry) endJob(domainID uint, token uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.jobs[domainID]
	if ok && entry.token == token {
		delete(r.jobs, domainID)
	}
}

func isCertJobActive(domainID uint, token uint64) bool {
	certJobs.mu.Lock()
	defer certJobs.mu.Unlock()
	entry, ok := certJobs.jobs[domainID]
	return ok && entry.token == token && entry.ctx.Err() == nil
}

// certJobInflight reports whether a certificate job is registered for domainID.
// The entry remains until the worker goroutine calls release(), even after cancellation.
func certJobInflight(domainID uint) bool {
	certJobs.mu.Lock()
	defer certJobs.mu.Unlock()
	_, ok := certJobs.jobs[domainID]
	return ok
}

func cancelCertJob(domainID uint) {
	certJobs.mu.Lock()
	defer certJobs.mu.Unlock()
	entry, ok := certJobs.jobs[domainID]
	if !ok {
		return
	}
	entry.cancel()
}

// CancelAllCertJobs cancels every in-flight certificate job (used during shutdown).
// Registry entries are removed when each worker goroutine finishes.
func CancelAllCertJobs() {
	certJobs.mu.Lock()
	defer certJobs.mu.Unlock()
	for domainID, entry := range certJobs.jobs {
		entry.cancel()
		slog.Debug("cancelled in-flight cert job", "domain_id", domainID)
	}
}
