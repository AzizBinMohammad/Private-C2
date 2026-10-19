// Package auditwriter persists hash-chained audit entries to the database.
package auditwriter

import (
	"fmt"
	"sync"

	"github.com/azizbinmohammad/private-c2/pkg/audit"
	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm"
)

// Writer implements audit.Writer on top of GORM.
type Writer struct {
	db           *gorm.DB
	mu           sync.Mutex
	previousHash string
}

// New loads the current chain head so writes continue the existing chain.
func New(db *gorm.DB) (*Writer, error) {
	if db == nil {
		return nil, fmt.Errorf("audit writer: nil database")
	}
	w := &Writer{db: db}
	var last []models.AuditEntry
	res := db.Order("created_at DESC").Limit(1).Find(&last)
	if res.Error != nil {
		return nil, fmt.Errorf("load audit chain head: %w", res.Error)
	}
	if len(last) == 1 {
		w.previousHash = last[0].EntryHash
	}
	return w, nil
}

// Head returns the current chain head.
func (w *Writer) Head() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.previousHash
}

// Write persists one entry. The entry must continue the chain this writer
// knows about; a discontinuity is refused rather than silently stored.
func (w *Writer) Write(entry audit.Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if entry.PreviousHash != w.previousHash {
		return fmt.Errorf("audit chain discontinuity: entry previous %q, writer head %q", entry.PreviousHash, w.previousHash)
	}
	row := models.AuditEntryFromLib(entry)
	if err := w.db.Create(&row).Error; err != nil {
		return fmt.Errorf("persist audit entry: %w", err)
	}
	w.previousHash = entry.EntryHash
	return nil
}
