package main

import (
	"errors"
	"log"
	"math"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

func (e *Exporter) pingLoop(interval, timeout, unreachableAt time.Duration) {
	log.Printf("ping: pinging %v every %s", e.addr, interval)

	unreachable := errors.New("no response")

	var errorStart time.Time
	var determined bool
	var markedUnreachable bool
	e.pingUp.WithLabelValues(e.addr).Set(math.NaN())

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
				e.pingUp.WithLabelValues(e.addr).Set(0)
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
				e.pingUp.WithLabelValues(e.addr).Set(1)
				markedUnreachable = false
				determined = true
			}
			e.pingTimes.WithLabelValues().Observe(float64(stats.AvgRtt.Seconds()))
		}

		elapsed := time.Since(start)
		next := interval - elapsed
		if next > 0 {
			time.Sleep(next)
		}
	}
}
