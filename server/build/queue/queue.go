package queue

import (
	"fmt"
	"sync"
	"time"
)

// JobStatus represents the current state of a build job.
type JobStatus string

const (
	JobPending   JobStatus = "pending"
	JobBuilding  JobStatus = "building"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"
)

// Job represents a single build request in the queue.
type Job struct {
	ID           string
	OperatorID   string
	EngagementID string
	Config       interface{} // *build.BuildConfig
	Status       JobStatus
	Error        string
	SHA256       string
	FileSize     int64
	ArtifactData []byte
	CreatedAt    time.Time
	StartedAt    *time.Time
	CompletedAt  *time.Time

	mu sync.RWMutex
}

// GetStatus returns the current job status in a thread-safe manner.
func (j *Job) GetStatus() JobStatus {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.Status
}

// SetStatus updates the job status in a thread-safe manner.
func (j *Job) SetStatus(status JobStatus) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = status
	now := time.Now()
	switch status {
	case JobBuilding:
		j.StartedAt = &now
	case JobCompleted, JobFailed:
		j.CompletedAt = &now
	}
}

// SetError marks the job as failed with the given error message.
func (j *Job) SetError(err string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = JobFailed
	j.Error = err
	now := time.Now()
	j.CompletedAt = &now
}

// SetResult stores the build result in the job.
func (j *Job) SetResult(sha256 string, fileSize int64, data []byte) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = JobCompleted
	j.SHA256 = sha256
	j.FileSize = fileSize
	j.ArtifactData = data
	now := time.Now()
	j.CompletedAt = &now
}

// BuildHandler is the function signature for build execution.
// Implementations receive a Job and produce the build artifact.
type BuildHandler func(job *Job) error

// Queue manages concurrent build jobs with configurable parallelism.
type Queue struct {
	mu           sync.RWMutex
	jobs         map[string]*Job
	pending      chan *Job
	handler      BuildHandler
	maxWorkers   int
	buildTimeout time.Duration
	stopCh       chan struct{}
	wg           sync.WaitGroup
	running      bool
}

// NewQueue creates a new build queue with the given parallelism and handler.
func NewQueue(maxWorkers int, buildTimeout time.Duration, handler BuildHandler) *Queue {
	if maxWorkers <= 0 {
		maxWorkers = 2
	}
	if buildTimeout <= 0 {
		buildTimeout = 15 * time.Minute
	}

	return &Queue{
		jobs:         make(map[string]*Job),
		pending:      make(chan *Job, 100),
		handler:      handler,
		maxWorkers:   maxWorkers,
		buildTimeout: buildTimeout,
		stopCh:       make(chan struct{}),
	}
}

// Start launches the worker goroutines.
func (q *Queue) Start() {
	q.mu.Lock()
	if q.running {
		q.mu.Unlock()
		return
	}
	q.running = true
	q.mu.Unlock()

	for i := 0; i < q.maxWorkers; i++ {
		q.wg.Add(1)
		go newWorker(i, q).run()
	}
}

// Stop signals all workers to stop and waits for them to finish.
func (q *Queue) Stop() {
	q.mu.Lock()
	if !q.running {
		q.mu.Unlock()
		return
	}
	q.running = false
	q.mu.Unlock()

	close(q.stopCh)
	q.wg.Wait()
}

// Submit adds a new build job to the queue and returns its ID.
func (q *Queue) Submit(job *Job) (string, error) {
	if job.ID == "" {
		return "", fmt.Errorf("job ID is required")
	}

	q.mu.Lock()
	if _, exists := q.jobs[job.ID]; exists {
		q.mu.Unlock()
		return "", fmt.Errorf("job %s already exists", job.ID)
	}

	job.Status = JobPending
	job.CreatedAt = time.Now()
	q.jobs[job.ID] = job
	q.mu.Unlock()

	select {
	case q.pending <- job:
		return job.ID, nil
	default:
		job.SetError("build queue is full")
		return "", fmt.Errorf("build queue is full")
	}
}

// GetJob returns the job with the given ID.
func (q *Queue) GetJob(id string) (*Job, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	job, ok := q.jobs[id]
	if !ok {
		return nil, fmt.Errorf("job %s not found", id)
	}
	return job, nil
}

// ListJobs returns all jobs, optionally filtered by status.
func (q *Queue) ListJobs(statusFilter JobStatus) []*Job {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var result []*Job
	for _, job := range q.jobs {
		if statusFilter == "" || job.GetStatus() == statusFilter {
			result = append(result, job)
		}
	}
	return result
}

// PendingCount returns the number of jobs waiting to be built.
func (q *Queue) PendingCount() int {
	return len(q.pending)
}

// ActiveCount returns the number of jobs currently building.
func (q *Queue) ActiveCount() int {
	q.mu.RLock()
	defer q.mu.RUnlock()

	count := 0
	for _, job := range q.jobs {
		if job.GetStatus() == JobBuilding {
			count++
		}
	}
	return count
}

// RemoveJob removes a completed or failed job from the queue.
func (q *Queue) RemoveJob(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	job, ok := q.jobs[id]
	if !ok {
		return fmt.Errorf("job %s not found", id)
	}

	status := job.GetStatus()
	if status == JobPending || status == JobBuilding {
		return fmt.Errorf("cannot remove job %s: status is %s", id, status)
	}

	delete(q.jobs, id)
	return nil
}
