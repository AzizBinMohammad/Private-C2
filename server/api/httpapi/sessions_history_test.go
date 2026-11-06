package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/server/c2"
	"github.com/azizbinmohammad/private-c2/server/store/models"
)

func authedGet(t *testing.T, router http.Handler, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestSessionHistoryAndTaskHistory(t *testing.T) {
	router, _, db := setupTestRouter(t)
	token := getAuthToken(t, router)
	now := time.Now()

	if err := db.Create(&models.Session{
		Base:         models.Base{ID: "sess-1"},
		Hostname:     "host-1",
		Username:     "user",
		HealthStatus: "active",
		ImplantID:    "implant-1",
		EngagementID: "eng-1",
		LastCheckin:  now,
	}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := db.Create(&models.Task{
		ID: "task-1", SessionID: "sess-1", ImplantID: "implant-1",
		EngagementID: "eng-1", Type: "shell", Args: "id", State: "completed", CreatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed task: %v", err)
	}
	if err := db.Create(&models.TaskResult{
		TaskID: "task-1", SessionID: "sess-1", Success: true, Output: "uid=0", CompletedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed result: %v", err)
	}

	w := authedGet(t, router, token, "/api/sessions/history")
	if w.Code != http.StatusOK {
		t.Fatalf("history status = %d: %s", w.Code, w.Body.String())
	}
	var sessions []models.Session
	if err := json.Unmarshal(w.Body.Bytes(), &sessions); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != "sess-1" {
		t.Fatalf("history = %+v", sessions)
	}

	w = authedGet(t, router, token, "/api/sessions/sess-1/tasks?limit=10")
	if w.Code != http.StatusOK {
		t.Fatalf("tasks status = %d: %s", w.Code, w.Body.String())
	}
	var tasks []models.Task
	if err := json.Unmarshal(w.Body.Bytes(), &tasks); err != nil {
		t.Fatalf("decode tasks: %v", err)
	}
	if len(tasks) != 1 || tasks[0].ID != "task-1" {
		t.Fatalf("tasks = %+v", tasks)
	}

	// The result is not in the live in-memory map, so the endpoint must fall
	// back to the persisted row.
	w = authedGet(t, router, token, "/api/tasks/task-1")
	if w.Code != http.StatusOK {
		t.Fatalf("result status = %d: %s", w.Code, w.Body.String())
	}
	var result c2.TaskResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.TaskID != "task-1" || !result.Success || result.Output != "uid=0" {
		t.Fatalf("result = %+v", result)
	}
}

func TestSessionHistory_PendingResultUsesPendingShape(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	token := getAuthToken(t, router)

	w := authedGet(t, router, token, "/api/tasks/unknown-task")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var pending PendingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &pending); err != nil {
		t.Fatalf("decode pending: %v", err)
	}
	if pending.Status != "pending" {
		t.Fatalf("pending status = %q", pending.Status)
	}
}
