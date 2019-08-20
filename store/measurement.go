package store

import (
	"errors"
	"github.com/aau-network-security/go-domains/models"
	"time"
)

var (
	ActiveMeasurementErr   = errors.New("measurement already running, must be stopped first")
	NoActiveMeasurementErr = errors.New("no measurement running")
)

func (s *Store) hasActiveMeasurement() bool {
	return s.curMeasurement.ID != 0
}

// starts a new measurement
func (s *Store) StartMeasurement(description, host string) error {
	if s.hasActiveMeasurement() {
		return ActiveMeasurementErr
	}
	measure := &models.Measurement{
		ID:          s.ids.measurements,
		Description: description,
		Host:        host,
		StartTime:   time.Now(),
	}

	if err := s.db.Insert(measure); err != nil {
		return err
	}
	s.curMeasurement = measure
	s.ids.measurements++
	return s.NextStage()
}

func (s *Store) stopStage() error {
	if s.curStage == nil {
		return nil
	}
	s.curStage.StopTime = time.Now()
	if err := s.db.Update(s.curStage); err != nil {
		return err
	}
	s.curStage = nil
	return nil
}

func (s *Store) NextStage() error {
	if !s.hasActiveMeasurement() {
		return NoActiveMeasurementErr
	}
	// stop current stage if exists
	if err := s.stopStage(); err != nil {
		return err
	}

	stage := &models.Stage{
		StartTime:     time.Now(),
		MeasurementID: s.curMeasurement.ID,
		ID:            s.ids.stages,
	}

	if err := s.db.Insert(stage); err != nil {
		return err
	}
	s.curStage = stage
	s.ids.stages++

	return nil
}

// stops the currently running measurements
func (s *Store) StopMeasurement() error {
	if !s.hasActiveMeasurement() {
		return NoActiveMeasurementErr
	}
	s.curMeasurement.EndTime = time.Now()
	if err := s.db.Update(s.curMeasurement); err != nil {
		return err
	}
	s.curMeasurement = nil
	return s.stopStage()
}
