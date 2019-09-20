package store

import (
	"errors"
	"github.com/aau-network-security/go-domains/models"
	"github.com/google/uuid"
	"strings"
	"time"
)

var (
	ActiveMeasurementErr   = errors.New("measurement already running, must be stopped first")
	NoActiveMeasurementErr = errors.New("no measurement running")
	NoActiveStageErr       = errors.New("no stage running")
)

type measurementState struct {
	measurements map[string]*models.Measurement
	stages       map[string]*models.Stage
}

func NewMeasurementState() measurementState {
	return measurementState{
		measurements: make(map[string]*models.Measurement),
		stages:       make(map[string]*models.Stage),
	}
}

func (ms *measurementState) MId(muid string) (uint, bool) {
	measure, ok := ms.measurements[muid]
	if !ok {
		return 0, false
	}
	return measure.ID, true
}

func (ms *measurementState) SId(muid string) (uint, bool) {
	stage, ok := ms.stages[muid]
	if !ok {
		return 0, false
	}
	return stage.ID, true
}

func newMId() string {
	uuid := uuid.New()
	return strings.Replace(uuid.String(), "-", "", -1)
}

// starts a new measurement
func (s *Store) StartMeasurement(description, host string) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	tm := time.Now()
	mid := newMId()
	measure := &models.Measurement{
		Mid:         mid,
		Description: description,
		Host:        host,
		StartTime:   tm,
		Stage:       1,
	}

	if err := tx.Insert(measure); err != nil {
		return "", err
	}

	stage := &models.Stage{
		MeasurementID: measure.ID,
		Stage:         1,
		StartTime:     tm,
	}

	if err := tx.Insert(stage); err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	s.ms.measurements[mid] = measure
	s.ms.stages[mid] = stage

	return mid, nil
}

func (s *Store) NextStage(mid string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	curStage, ok := s.ms.stages[mid]
	if !ok {
		return NoActiveStageErr
	}
	tm := time.Now()

	curStage.StopTime = tm

	if err := tx.Update(curStage); err != nil {
		return err
	}

	newStage := &models.Stage{
		StartTime:     time.Now(),
		MeasurementID: curStage.MeasurementID,
		Stage:         curStage.ID + 1,
	}

	if err := tx.Insert(newStage); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return nil
	}

	s.ms.stages[mid] = newStage

	return nil
}

// stops the currently running measurements
func (s *Store) StopMeasurement(mid string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	measure, ok := s.ms.measurements[mid]
	if !ok {
		return NoActiveMeasurementErr
	}

	stage, ok := s.ms.stages[mid]
	if !ok {
		return NoActiveStageErr
	}
	tm := time.Now()

	// stop stage
	stage.StopTime = tm
	if err := tx.Update(stage); err != nil {
		return err
	}

	measure.EndTime = tm
	if err := tx.Update(measure); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	delete(s.ms.measurements, mid)
	delete(s.ms.stages, mid)

	return nil
}
