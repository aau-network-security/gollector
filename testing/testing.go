package testing

import (
	"fmt"
	"github.com/aau-network-security/go-domains/models"
	"github.com/jinzhu/gorm"
	"os"
	"testing"
)

func SkipCI(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping testing in CI environment")
	}
}

func ResetDb(g *gorm.DB) error {
	tables := []string{
		"apexes",
		"zonefile_entries",
		"tlds",
		"fqdns",
		"certificate_to_fqdns",
		"certificates",
		"log_entries",
		"logs",
		"record_types",
		"passive_entries",
		"measurements",
		"stages",
	}

	for _, table := range tables {
		qry := fmt.Sprintf("DROP TABLE IF EXISTS %s", table)
		if err := g.Exec(qry).Error; err != nil {
			return err
		}
	}

	migrateExamples := []interface{}{
		&models.Apex{},
		&models.ZonefileEntry{},
		&models.Tld{},
		&models.Fqdn{},
		&models.CertificateToFqdn{},
		&models.Certificate{},
		&models.LogEntry{},
		&models.Log{},
		&models.RecordType{},
		&models.PassiveEntry{},
		&models.Measurement{},
		&models.Stage{},
	}
	for _, ex := range migrateExamples {
		if err := g.AutoMigrate(ex).Error; err != nil {
			return err
		}
	}
	return nil
}
