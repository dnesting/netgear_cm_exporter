package main

import (
	"context"
	"errors"
	"log"
	"math"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

func (e *Exporter) ensureModemID(ctx context.Context) {
	e.mu.Lock()
	select {
	case <-e.gotModemID:
	default:
		var err error
		log.Printf("ping: collecting modem info")
		done := make(chan struct{})
		//go func() {
		//	_, _, err = e.retrieveModemInfo()
		//	close(done)
		//}()
		go func() {
			e.callAuthenticated(func() error {
				_, _, err := e.retrieveModemInfo()
				return err
			})
			close(done)
		}()
		select {
		case <-done:
		case <-e.gotModemID:
		case <-ctx.Done():
			err = ctx.Err()
		}
		if err != nil {
			log.Printf("ping: failed to collect modem info, will use blank labels for MAC and serial: %v", err)
		}
	}
	e.mu.Unlock()
}

func (e *Exporter) pingLoop(interval, timeout, unreachableAt time.Duration) {
	unreachable := errors.New("no response")

	var errorStart time.Time
	var determined bool
	var markedUnreachable bool
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	e.ensureModemID(ctx)
	cancel()

	e.pingUp.WithLabelValues(e.addr, e.modemID.SerialNumber, e.modemID.MacAddress).Set(math.NaN())

	log.Printf("ping: pinging %v every %s", e.addr, interval)

	for {
		pinger, err := probing.NewPinger(e.addr)
		if err != nil {
			panic(err)
		}

		pinger.Count = 1
		pinger.Interval = time.Second
		pinger.Timeout = timeout

		start := time.Now()
		err = pinger.Run()
		stats := pinger.Statistics()

		if err != nil || stats.PacketsRecv == 0 {
			if errorStart.IsZero() {
				errorStart = time.Now()
				if err == nil {
					err = unreachable
				}
				log.Printf("ping %s: %v", e.addr, err)
			}
			if !markedUnreachable && time.Since(errorStart) > unreachableAt {
				e.pingUp.WithLabelValues(e.addr, e.modemID.SerialNumber, e.modemID.MacAddress).Set(0)
				markedUnreachable = true
				determined = true
				log.Printf("ping %s: marking unreachable", e.addr)
			}
		} else {
			// err == nil && pinger.Statistics().PacketsRecv > 0

			if !errorStart.IsZero() {
				log.Printf("ping %s: reachable after %v", e.addr, time.Since(errorStart))
				errorStart = time.Time{}
			}
			if markedUnreachable || !determined {
				e.pingUp.WithLabelValues(e.addr, e.modemID.SerialNumber, e.modemID.MacAddress).Set(1)
				markedUnreachable = false
				determined = true
			}
			secs := float64(stats.AvgRtt.Seconds())
			e.pingTimes.WithLabelValues(e.addr, e.modemID.SerialNumber, e.modemID.MacAddress).Observe(secs)
			e.pingTime.WithLabelValues(e.addr, e.modemID.SerialNumber, e.modemID.MacAddress).Set(secs)
		}

		elapsed := time.Since(start)
		next := interval - elapsed
		if next > 0 {
			time.Sleep(next)
		}
	}
}
