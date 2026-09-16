package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSequenceRegressionNeverEmitsHealthyRecord(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := validDependencies(ctx, cancel)
	checks, notifications, waits := 0, 0, 0
	var output bytes.Buffer
	d.output = &output
	d.check = func(context.Context, string) ([]byte, error) {
		checks++
		sequence := int64(4 - checks)
		return json.Marshal(report{"checkpoint_verified", sequence, sequence, true})
	}
	d.notify = func(string) error { notifications++; return nil }
	d.wait = func(context.Context) error { waits++; return nil }
	code, reason := run(ctx, []string{"--config", recoveryConfig}, d)
	if code != 69 || reason != "sequence_regressed" || checks != 2 || notifications != 1 || waits != 1 ||
		strings.Count(output.String(), "checkpoint_verified") != 1 {
		t.Fatal("sequence regression reached output, watchdog or continued execution")
	}
}

func TestSequenceCanRemainEqualOrAdvance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := validDependencies(ctx, cancel)
	sequences := []int64{2, 2, 7, 7}
	index, notifications := 0, 0
	d.check = func(context.Context, string) ([]byte, error) {
		sequence := sequences[index]
		return json.Marshal(report{"checkpoint_verified", sequence, sequence, true})
	}
	d.notify = func(message string) error {
		if strings.Contains(message, "READY=1\n") != (index == 0) {
			t.Fatal("unexpected readiness repeat")
		}
		notifications++
		return nil
	}
	d.wait = func(context.Context) error {
		index++
		if index == len(sequences) {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	if code, reason := run(ctx, []string{"--config", recoveryConfig}, d); code != 0 || reason != "" || notifications != 4 {
		t.Fatal("valid sequence progression rejected")
	}
}
