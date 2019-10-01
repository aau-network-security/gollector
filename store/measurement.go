package store

import (
	"errors"
	"github.com/aau-network-security/go-domains/store/models"
	"github.com/go-pg/pg"
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

func newMuId() string {
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
	muid := newMuId()
	measure := &models.Measurement{
		Muid:        muid,
		Description: description,
		Host:        host,
		StartTime:   tm,
		Stage:       1,
	}

	if err := tx.Insert(measure); err != nil {
		return "", err
	}

	stage, err := s.startStage(tx, muid, measure.ID, tm)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	s.ms.measurements[muid] = measure
	s.ms.stages[muid] = stage

	return muid, nil
}

// stops the currently running measurements
func (s *Store) StopMeasurement(muid string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	measure, ok := s.ms.measurements[muid]
	if !ok {
		return NoActiveMeasurementErr
	}

	// stop stage
	if err := s.stopStage(tx, muid); err != nil {
		return err
	}

	// stop measurement
	measure.EndTime = time.Now()
	if err := tx.Update(measure); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	delete(s.ms.measurements, muid)
	delete(s.ms.stages, muid)

	return s.RunPostHooks()
}

// starts a new stage
func (s *Store) startStage(tx *pg.Tx, muid string, mid uint, tm time.Time) (*models.Stage, error) {
	curStage, ok := s.ms.stages[muid]
	var stageId uint
	switch ok {
	case true:
		// bump stage id
		stageId = curStage.ID + 1
	case false:
		// first stage of measurement
		stageId = 1
	}

	newStage := &models.Stage{
		MeasurementID: mid,
		Stage:         stageId,
		StartTime:     tm,
	}

	return newStage, tx.Insert(newStage)
}

func (s *Store) StartStage(muid string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	measure, ok := s.ms.measurements[muid]
	if !ok {
		return NoActiveMeasurementErr
	}

	newStage, err := s.startStage(tx, muid, measure.ID, time.Now())
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.ms.stages[muid] = newStage

	return nil
}

// stops the stage that is currently running
func (s *Store) stopStage(tx *pg.Tx, muid string) error {
	curStage, ok := s.ms.stages[muid]
	if !ok {
		return NoActiveStageErr
	}
	tm := time.Now()

	curStage.StopTime = tm

	return tx.Update(curStage)
}

func (s *Store) StopStage(muid string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := s.stopStage(tx, muid); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return s.RunPostHooks()
}
