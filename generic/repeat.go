package generic

import (
	"github.com/rs/zerolog/log"
	"time"
)

// repeats the execution of a function n times at a given interval
// if n is negative, repeat infinitely
func Repeat(f func(t time.Time) error, startTime time.Time, interval time.Duration, n int) error {
	untilStart := startTime.Sub(time.Now())

	if untilStart > 0 {
		log.Debug().Msgf("Waiting %s before starting function", untilStart)
		<-time.After(untilStart)
	}

	errc := make(chan error)

	t := startTime

	for n != 0 {
		log.Debug().Msgf("Performing function at %s (%d remaining)", t, n)
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
	}
	close(errc)

	return nil
}
