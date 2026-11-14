package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportServiceTimezonePolicy(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	for _, zone := range []string{"Local", "EST", "CET", "GMT", "EST5EDT", "+05:30", " UTC "} {
		t.Run(zone, func(t *testing.T) {
			_, err := BuildAnalyticsFilter(AnalyticsRequest{Timezone: zone}, now)
			require.Error(t, err)
			_, err = BuildUsageFilter(UsageRequest{Timezone: zone}, ModelGroups{})
			require.Error(t, err)
			_, _, err = BuildActivityReportSelection(ActivityReportRequest{Timezone: zone}, now)
			require.Error(t, err)
		})
	}
	usage, err := BuildUsageFilter(UsageRequest{}, ModelGroups{})
	require.NoError(t, err)
	assert.Equal(t, "UTC", usage.Timezone)
	analytics, err := BuildAnalyticsFilter(AnalyticsRequest{}, now)
	require.NoError(t, err)
	assert.Equal(t, "UTC", analytics.Timezone)
	q, _, err := BuildActivityReportSelection(ActivityReportRequest{}, now)
	require.NoError(t, err)
	assert.Equal(t, "UTC", q.Timezone)
}
