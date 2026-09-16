package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Exercise steady-state transitions without wall-clock sleeps or a provider.
func TestVerifiedLifecycleAndWatchdogBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := validDependencies(ctx, cancel)
	intervals := []int64{60000, 3600000, 120000, 60000}
	sequences := []int64{3, 3, 7, 7} // Idempotence and forward gaps are permitted.
	index := 0
	notifications := 0
	d.check = func(context.Context, string) ([]byte, error) {
		return json.Marshal(report{"anchor_verified", sequences[index], intervals[index]})
	}
	d.notify = func(message string) error {
		expected := time.Duration(intervals[index])*time.Millisecond + checkDeadline + 10*time.Second
		if !strings.Contains(message, fmt.Sprintf("WATCHDOG_USEC=%d\n", expected.Microseconds())) ||
			!strings.Contains(message, "WATCHDOG=1\n") ||
			strings.Contains(message, "READY=1\n") != (index == 0) || expected >= 3700*time.Second {
			t.Fatal("invalid verified watchdog notification")
		}
		notifications++
		return nil
	}
	d.wait = func(_ context.Context, duration time.Duration) error {
		if duration != time.Duration(intervals[index])*time.Millisecond || notifications != index+1 {
			t.Fatal("interval or notification sequence changed")
		}
		index++
		if index == len(intervals) {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	if code, reason := run(ctx, []string{"--config", exporterConfig}, d); code != 0 || reason != "" || notifications != 4 {
		t.Fatal("verified lifecycle did not finish")
	}
}

func TestSequenceRegressionNeverEmitsHealthyRecord(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := validDependencies(ctx, cancel)
	checks, notifications, waits := 0, 0, 0
	var output bytes.Buffer
	d.output = &output
	d.check = func(context.Context, string) ([]byte, error) {
		checks++
		return json.Marshal(report{"anchor_verified", int64(4 - checks), 60000})
	}
	d.notify = func(string) error { notifications++; return nil }
	d.wait = func(context.Context, time.Duration) error { waits++; return nil }
	code, reason := run(ctx, []string{"--config", exporterConfig}, d)
	if code != 69 || reason != "sequence_regressed" || checks != 2 || notifications != 1 || waits != 1 ||
		output.String() != success+"\n" {
		t.Fatal("sequence regression reached output, watchdog or continued execution")
	}
}

func TestRejectedRecordCannotAdjustWatchdog(t *testing.T) {
	for _, raw := range []string{"private detail", strings.Replace(success, "60000", "3600001", 1),
		strings.Replace(success, `"anchor_verified"`, `"published"`, 1)} {
		t.Run(raw[:1], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d := validDependencies(ctx, cancel)
			d.check = func(context.Context, string) ([]byte, error) { return []byte(raw), nil }
			notified := false
			d.notify = func(string) error { notified = true; return nil }
			if code, _ := run(ctx, []string{"--config", exporterConfig}, d); code != 70 || notified {
				t.Fatal("unverified record changed watchdog")
			}
		})
	}
}
