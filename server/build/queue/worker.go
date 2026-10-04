package queue

import (
	"fmt"
	"os"
	"time"
)

// worker processes build jobs from the queue.
type worker struct {
	id    int
	queue *Queue
}

// newWorker creates a new worker bound to the given queue.
func newWorker(id int, q *Queue) *worker {
	return &worker{id: id, queue: q}
}

// run is the main worker loop. It pulls jobs from the pending channel,
// executes the build handler, and stores the result.
func (w *worker) run() {
	defer w.queue.wg.Done()

	for {
		select {
		case <-w.queue.stopCh:
			return
		case job, ok := <-w.queue.pending:
			if !ok {
				return
			}
			w.processJob(job)
		}
	}
}

// processJob executes a single build job with timeout and cleanup.
func (w *worker) processJob(job *Job) {
	job.SetStatus(JobBuilding)

	// Create a temporary working directory for this build.
	workDir, err := os.MkdirTemp("", fmt.Sprintf("pc2-build-%s-", job.ID))
	if err != nil {
		job.SetError(fmt.Sprintf("create temp dir: %v", err))
		return
	}

	// Ensure cleanup of temporary files regardless of outcome.
	defer cleanupWorkDir(workDir)

	// Execute the build with a timeout.
	done := make(chan error, 1)
	go func() {
		done <- w.queue.handler(job)
	}()

	select {
	case err := <-done:
		if err != nil {
			job.SetError(err.Error())
		}
		// On success, the handler is expected to have called job.SetResult.
	case <-time.After(w.queue.buildTimeout):
		job.SetError(fmt.Sprintf("build timed out after %s", w.queue.buildTimeout))
	case <-w.queue.stopCh:
		job.SetError("build cancelled: queue shutting down")
	}
}

// cleanupWorkDir removes the temporary build directory and all its contents.
func cleanupWorkDir(dir string) {
	if dir == "" {
		return
	}
	_ = os.RemoveAll(dir)
}
