package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederationJobRunsFullAtStartupHourlyAndAfterFailure(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var full []bool
	fail := false
	job := newFederationPushJob(func(ctx context.Context, inventory bool) error {
		full = append(full, inventory)
		if fail {
			return errors.New("offline")
		}
		return nil
	}, func() time.Time { return now })
	assert.True(t, job.RunAtStart)
	assert.Equal(t, 15*time.Minute, job.Interval)
	require.NoError(t, job.Run(t.Context()))
	now = now.Add(15 * time.Minute)
	require.NoError(t, job.Run(t.Context()))
	now = now.Add(45 * time.Minute)
	fail = true
	require.Error(t, job.Run(t.Context()))
	fail = false
	now = now.Add(15 * time.Minute)
	require.NoError(t, job.Run(t.Context()))
	assert.Equal(t, []bool{true, false, true, true}, full)
}
