package store

import (
	"fmt"
	"time"

	"github.com/azizbinmohammad/private-c2/server/store/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Config struct {
	Dialect         string // sqlite, postgres
	DSN             string
	MaxIdleConns    int
	MaxOpenConns    int
	ConnMaxLifetime time.Duration
	LogLevel        logger.LogLevel
}

func DefaultConfig() Config {
	return Config{
		Dialect:         "sqlite",
		DSN:             "private-c2.db",
		MaxIdleConns:    10,
		MaxOpenConns:    100,
		ConnMaxLifetime: time.Hour,
		LogLevel:        logger.Warn,
	}
}

func Open(cfg Config) (*gorm.DB, error) {
	gormCfg := &gorm.Config{
		Logger:      logger.Default.LogMode(cfg.LogLevel),
		PrepareStmt: true,
	}

	var dialector gorm.Dialector
	switch cfg.Dialect {
	case "sqlite":
		dialector = sqlite.Open(cfg.DSN)
	case "postgres":
		dialector = postgres.Open(cfg.DSN)
	default:
		return nil, fmt.Errorf("unsupported database dialect: %s", cfg.Dialect)
	}

	db, err := gorm.Open(dialector, gormCfg)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("getting sql.DB: %w", err)
	}

	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	if cfg.Dialect == "sqlite" && cfg.DSN == ":memory:" {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	}

	return db, nil
}

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.Engagement{},
		&models.Operator{},
		&models.Session{},
		&models.Beacon{},
		&models.Listener{},
		&models.PayloadArtifact{},
		&models.AuditEntry{},
		&models.C2Profile{},
		&models.Role{},
		// OT/ICS models
		&models.OTAssetRecord{},
		&models.OTCredentialFinding{},
		&models.OTVulnFinding{},
		&models.OTSegmentationGap{},
		&models.OTComplianceFinding{},
		&models.OTTopologyEdge{},
		&models.OTCaptureSession{},
		&models.OTAssessmentReport{},
		&models.OTHMIFinding{},
		&models.OTWirelessFinding{},
	)
}
