package store

import (
	"errors"
	"strings"
	"time"

	errs "github.com/pkg/errors"

	"github.com/aau-network-security/gollector/store/models"
	"github.com/google/uuid"
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
	//tx, err := s.db.Begin()
	//if err != nil {
	//	return "", err
	//}
	//defer tx.Rollback()

	//todo implement ids++ for stage and measurement
	tm := time.Now()
	muid := newMuId()
	measure := &models.Measurement{
		ID:          1,
		Muid:        muid,
		Description: description,
		Host:        host,
		StartTime:   tm,
		Stage:       1,
	}

	if err := s.db.Query(`INSERT INTO measurements (id, muid, description, host, start_time) VALUES (?, ?, ?, ?, ?)`,
		measure.ID, measure.Muid, measure.Description, measure.Host, measure.StartTime).Exec(); err != nil {
		return "", err
	}

	stage, err := s.startStage(muid, measure.ID, tm)
	if err != nil {
		return "", err
	}

	s.ms.measurements[muid] = measure
	s.ms.stages[muid] = stage

	return muid, nil
}

// stops the currently running measurements
func (s *Store) StopMeasurement(muid string) error {
	//tx, err := s.db.Begin()
	//if err != nil {
	//	return err
	//}
	//defer tx.Rollback()

	_, ok := s.ms.measurements[muid]
	if !ok {
		return NoActiveMeasurementErr
	}

	// stop stage
	if err := s.stopStage(muid); err != nil {
		return err
	}
	//todo update the db
	//// stop measurement
	//measure.EndTime = time.Now()
	//if err := tx.Update(measure); err != nil {
	//	return err
	//}
	//
	//if err := tx.Commit(); err != nil {
	//	return err
	//}

	delete(s.ms.measurements, muid)
	delete(s.ms.stages, muid)

	return s.RunPostHooks()
}

// starts a new stage
func (s *Store) startStage(muid string, mid uint, tm time.Time) (*models.Stage, error) {
	curStage, ok := s.ms.stages[muid]
	var stageId uint
	switch ok {
	case true:
		// bump stage id
		stageId = curStage.Stage + 1
	case false:
		// first stage of measurement
		stageId = 1
	}

	newStage := &models.Stage{
		ID:            1,
		MeasurementID: mid,
		Stage:         stageId,
		StartTime:     tm,
	}

	if err := s.db.Query(`INSERT INTO stages (id, measurement_id, stage, start_time) VALUES (?, ?, ?, ?)`,
		newStage.ID, newStage.MeasurementID, newStage.Stage, newStage.StartTime).Exec(); err != nil {
		return newStage, err
	}

	return newStage, nil
}

func (s *Store) StartStage(muid string) error {
	//tx, err := s.db.Begin()
	//if err != nil {
	//	return err
	//}
	//defer tx.Rollback()

	measure, ok := s.ms.measurements[muid]
	if !ok {
		return NoActiveMeasurementErr
	}

	newStage, err := s.startStage(muid, measure.ID, time.Now())
	if err != nil {
		return err
	}

	s.ms.stages[muid] = newStage

	return nil
}

// stops the stage that is currently running
func (s *Store) stopStage(muid string) error {
	curStage, ok := s.ms.stages[muid]
	if !ok {
		return NoActiveStageErr
	}
	tm := time.Now()

	curStage.StopTime = tm

	//todo update the db
	return nil
}

func (s *Store) StopStage(muid string) error {
	//tx, err := s.db.Begin()
	//if err != nil {
	//	return errs.Wrap(err, "beginning transaction")
	//}
	//defer tx.Rollback()

	if err := s.stopStage(muid); err != nil {
		return errs.Wrap(err, "stopping stage")
	}
	//
	//if err := tx.Commit(); err != nil {
	//	return errs.Wrap(err, "committing transaction")
	//}

	return s.RunPostHooks()
}
