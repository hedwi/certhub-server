package controllers

import "sync"

// ResetTestState clears in-memory cert job tracking between tests.
func ResetTestState() {
	certJobWG = sync.WaitGroup{}
	certJobs = certJobRegistry{jobs: make(map[uint]*certJobEntry)}
	certJobTokenSeq = 0
	domainWorkerByID = sync.Map{}
	certJobSlots = nil
	certJobSlotsOnce = sync.Once{}
}
