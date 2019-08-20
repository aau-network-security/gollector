package generic

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
		go func() {
			if err := f(t); err != nil {
				errc <- err
				return
			}
		}()

		select {
		case err := <-errc:
			return err
		case <-time.After(interval):
			// do
		}
		t = t.Add(interval)

		if n > 0 {
			n--
		}
		msg := fmt.Sprintf("Next scheduled at %s", t)
		if n >= 0 {
			msg += fmt.Sprintf(" (%d remaining)", n)
		}
		log.Debug().Msgf(msg)
	}

	return nil
}
