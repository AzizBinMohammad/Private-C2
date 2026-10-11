package store

import (
	"testing"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/gorm/logger"
)

func TestOpenMemory_MigrateAndQuery(t *testing.T) {
	db, err := Open(Config{
		Dialect:  "sqlite",
		DSN:      ":memory:",
		LogLevel: logger.Silent,
	})
	if err != nil {
		t.Fatalf("Open :memory: failed: %v", err)
	}

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate :memory: failed: %v", err)
	}

	op := models.Operator{Name: "testop", Role: "operator"}
	if err := db.Create(&op).Error; err != nil {
		t.Fatalf("Create operator failed: %v", err)
	}
	if op.ID == "" {
		t.Fatal("expected auto-generated UUID, got empty string")
	}

	var found models.Operator
	if err := db.First(&found, "id = ?", op.ID).Error; err != nil {
		t.Fatalf("Query operator back failed: %v", err)
	}
	if found.Name != "testop" {
		t.Fatalf("expected name 'testop', got %q", found.Name)
	}
}
