package app

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"time"
)

type RepeatFunc func(t time.Time) error

// repeats the execution of a function n times at a given interval
// if n is negative, repeat infinitely
func Repeat(f RepeatFunc, startTime time.Time, interval time.Duration, n int) error {
	untilStart := startTime.Sub(time.Now())

	if untilStart > 0 {
		msg := fmt.Sprintf("Next scheduled at %s", time.Now().Add(untilStart))
		if n >= 0 {
			msg += fmt.Sprintf(" (%d remaining)", n)
		}
		log.Debug().Msgf(msg)
		<-time.After(untilStart)
	}

	errc := make(chan error)
	defer close(errc)

	t := startTime

	for n != 0 {
		t = t.Add(interval)
		go func() {
			if err := f(t); err != nil {
				errc <- err
				return
			}
			msg := fmt.Sprintf("Next scheduled at %s", t)
			if n >= 0 {
				msg += fmt.Sprintf(" (%d remaining)", n)
			}
			log.Debug().Msgf(msg)
		}()

		select {
		case err := <-errc:
			return err
		case <-time.After(interval):
			// do again
		}

		if n > 0 {
			n--
		}
	}

	return nil
}

// unix time in milliseconds
func TimeFromUnix(ts int64) time.Time {
	return time.Unix(int64(ts/1000), int64(ts%1000))
}

// retries the given function up to "retries" times in case the function returns an error
func Retry(f func() error, retries int) error {
	if err := f(); err != nil {
		if retries == 0 {
			return err
		}
		return Retry(f, retries-1)
	}
	return nil
}
