package auditwriter

import (
	"path/filepath"
	"testing"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/store"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	cfg := store.DefaultConfig()
	cfg.DSN = filepath.Join(t.TempDir(), "audit.db")
	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestWriter_PersistsAndChains(t *testing.T) {
	db := testDB(t)
	writer, err := New(db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger := audit.NewLoggerFromHead(writer.Head(), writer)

	for i := 0; i < 3; i++ {
		if err := logger.Log("op-1", "eng-1", "sess-1", audit.EventSessionInteract,
			"task", "10.0.0.1", "ok", map[string]any{"i": i}, "127.0.0.1", ""); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	var rows []models.AuditEntry
	if err := db.Order("created_at ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	prev := ""
	for i, row := range rows {
		if row.PreviousHash != prev {
			t.Fatalf("row %d previous hash = %q, want %q", i, row.PreviousHash, prev)
		}
		entry, err := models.AuditEntryToLib(row)
		if err != nil {
			t.Fatalf("convert row %d: %v", i, err)
		}
		if got := audit.ComputeEntryHash(entry); got != row.EntryHash {
			t.Fatalf("row %d hash mismatch: %s != %s", i, got, row.EntryHash)
		}
		prev = row.EntryHash
	}
}

func TestWriter_ContinuesExistingChain(t *testing.T) {
	db := testDB(t)
	first, _ := New(db)
	if err := audit.NewLoggerFromHead(first.Head(), first).Log("op", "", "", audit.EventOperatorLogin, "login", "", "ok", nil, "", ""); err != nil {
		t.Fatal(err)
	}

	second, err := New(db)
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	if err := audit.NewLoggerFromHead(second.Head(), second).Log("op", "", "", audit.EventOperatorLogout, "logout", "", "ok", nil, "", ""); err != nil {
		t.Fatalf("second Log: %v", err)
	}

	var rows []models.AuditEntry
	db.Order("created_at ASC").Find(&rows)
	if len(rows) != 2 || rows[1].PreviousHash != rows[0].EntryHash {
		t.Fatalf("chain was not continued: %+v", rows)
	}
}

func TestWriter_RejectsDiscontinuity(t *testing.T) {
	db := testDB(t)
	writer, _ := New(db)
	err := writer.Write(audit.Entry{
		ID:           "bad",
		EventType:    audit.EventSessionInteract,
		PreviousHash: "not-the-head",
	})
	if err == nil {
		t.Fatal("discontinuous entry was accepted")
	}
}
