package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hedwi/certhub-server/config"
)

func TestBeginCertJob_UsesGeneratingTimeoutDeadline(t *testing.T) {
	saved := config.Cfg
	t.Cleanup(func() { config.Cfg = saved })

	config.Cfg.Renewal.GeneratingTimeout = "50ms"

	ctx, _, release := beginCertJob(99)
	defer release()

	jobDeadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected cert job context to have a deadline")
	}
	want := time.Now().Add(config.Cfg.Renewal.GeneratingTimeoutDuration())
	if jobDeadline.Before(want.Add(-20*time.Millisecond)) || jobDeadline.After(want.Add(20*time.Millisecond)) {
		t.Fatalf("deadline=%v, want ~%v", jobDeadline, want)
	}

	time.Sleep(60 * time.Millisecond)
	if err := ctx.Err(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestCertJobRegistrySingleDomain(t *testing.T) {
	ctx, token, release := beginCertJob(1)
	defer release()

	if !isCertJobActive(1, token) {
		t.Fatal("expected job to be active")
	}
	if !certJobInflight(1) {
		t.Fatal("expected job to be in flight")
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("expected live context, got %v", err)
	}

	release()
	if certJobInflight(1) {
		t.Fatal("expected job to be released")
	}
	if isCertJobActive(1, token) {
		t.Fatal("expected superseded job to be inactive")
	}
}

func TestCertJobRegistrySupersedesPriorJob(t *testing.T) {
	_, token1, release1 := beginCertJob(42)
	release1()

	_, token2, release2 := beginCertJob(42)
	defer release2()

	if token2 == token1 {
		t.Fatal("expected new token after supersede")
	}
	if !isCertJobActive(42, token2) {
		t.Fatal("new job token should be active")
	}
}

func TestBeginCertJob_WaitsForPriorWorker(t *testing.T) {
	saved := config.Cfg
	t.Cleanup(func() { config.Cfg = saved })
	config.Cfg.Renewal.GeneratingTimeout = "200ms"

	workerDone := beginDomainWorker(5)
	_, _, release1 := beginCertJob(5)
	cancelCertJob(5)

	releaseDone := make(chan struct{})
	go func() {
		time.Sleep(40 * time.Millisecond)
		release1()
		workerDone()
		close(releaseDone)
	}()

	before := time.Now()
	_, token2, release2 := beginCertJob(5)
	defer release2()
	if elapsed := time.Since(before); elapsed < 30*time.Millisecond {
		t.Fatalf("beginCertJob returned too soon: %v", elapsed)
	}
	<-releaseDone
	if !isCertJobActive(5, token2) {
		t.Fatal("expected replacement job to be active")
	}
}

func TestCancelCertJob(t *testing.T) {
	ctx, token, release := beginCertJob(7)

	cancelCertJob(7)

	if !certJobInflight(7) {
		t.Fatal("expected job to remain in flight until worker release")
	}
	if err := ctx.Err(); err == nil {
		t.Fatal("expected cancelled context")
	}
	if isCertJobActive(7, token) {
		t.Fatal("cancelled job should not be active")
	}

	release()
	if certJobInflight(7) {
		t.Fatal("expected job to be released after worker done")
	}
}

func TestCancelAllCertJobs(t *testing.T) {
	ctx1, _, release1 := beginCertJob(10)
	ctx2, _, release2 := beginCertJob(11)

	CancelAllCertJobs()

	if !certJobInflight(10) || !certJobInflight(11) {
		t.Fatal("expected jobs to remain registered until workers release")
	}
	if ctx1.Err() == nil || ctx2.Err() == nil {
		t.Fatal("expected all contexts cancelled")
	}

	release1()
	release2()

	if certJobInflight(10) || certJobInflight(11) {
		t.Fatal("expected all jobs released after workers done")
	}
}
