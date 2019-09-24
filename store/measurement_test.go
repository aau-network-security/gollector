package store

import (
	"github.com/aau-network-security/go-domains/store/models"
	"testing"
)

func TestMeasurement(t *testing.T) {
	conf := Config{
		Host:     "localhost",
		User:     "postgres",
		Password: "postgres",
		Port:     10001,
		DBName:   "domains",
	}

	s, g, err := openStore(conf)
	if err != nil {
		t.Fatalf("error while opening store: %s", err)
	}

	// start measurement(1)
	mid1, err := s.StartMeasurement("first", "test.local")
	if err != nil {
		t.Fatalf("failed to start first measurement: %s", err)
	}

	// start measurement(2)
	mid2, err := s.StartMeasurement("second", "test.local")
	if err != nil {
		t.Fatalf("failed to start second measurement: %s", err)
	}

	// update stage(1)
	if err := s.NextStage(mid1); err != nil {
		t.Fatalf("failed to start next stage for first measurement: %s", err)
	}

	// stop measurement(2)
	if err := s.StopMeasurement(mid2); err != nil {
		t.Fatalf("failed to stop second measurement: %s", err)
	}

	// check results in db
	var measurements []*models.Measurement
	if err := g.Find(&measurements).Error; err != nil {
		t.Fatalf("failed to retrieve measurements from db: %s", err)
	}

	var stages []*models.Stage
	if err := g.Order("id asc").Find(&stages).Error; err != nil {
		t.Fatalf("failed to retrieve stages from db: %s", err)
	}

	if len(measurements) != 2 {
		t.Fatalf("expected %d measurements, but got %d", 2, len(measurements))
	}
	if !measurements[0].EndTime.IsZero() {
		t.Fatalf("expected first measurement to be unstopped, but it is stopped")
	}
	if measurements[1].EndTime.IsZero() {
		t.Fatalf("expected second measurement to be stopped, but it is not")
	}

	if len(stages) != 3 {
		t.Fatalf("expected %d stages, but got %d", 2, len(stages))
	}
	if stages[0].MeasurementID != 1 || stages[2].MeasurementID != 1 {
		t.Fatalf("expected stages to belong to measurement %d, but they don't", 1)
	}
	if stages[1].MeasurementID != 2 {
		t.Fatalf("expected stage to belong to measurement %d, but it doesn't", 2)
	}
}
