package main

import (
	"os"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.kenn.io/agentsview/internal/config"
	"go.kenn.io/agentsview/internal/dbtest"
)

func TestUsageWindowCivilMidnights(t *testing.T) {
	for _, tc := range []struct{ zone, date, start, end string }{
		{"America/Santiago", "2026-09-06", "2026-09-06T04:00:00Z", "2026-09-07T02:59:59.999Z"},
		{"America/Havana", "2026-03-08", "2026-03-08T05:00:00Z", "2026-03-09T03:59:59.999Z"},
		{"Asia/Jerusalem", "2000-10-06", "2000-10-05T21:00:00Z", "2000-10-06T21:59:59.999Z"},
	} {
		t.Run(tc.zone, func(t *testing.T) {
			loc, err := time.LoadLocation(tc.zone)
			require.NoError(t, err)
			start, end, err := resolveCursorUsageWindow(UsageCursorConfig{Since: tc.date, Until: tc.date}, loc)
			require.NoError(t, err)
			assert.Equal(t, tc.start, start.Format(time.RFC3339Nano))
			assert.Equal(t, tc.end, end.Format(time.RFC3339Nano))
			point, date, err := resolveUsageWindowPoint(tc.date, time.Now(), loc)
			require.NoError(t, err)
			assert.Equal(t, tc.date, date)
			assert.Equal(t, tc.start, point.UTC().Format(time.RFC3339))
		})
	}
	loc, err := time.LoadLocation("Pacific/Apia")
	require.NoError(t, err)
	_, _, err = resolveCursorUsageWindow(UsageCursorConfig{Since: "2011-12-30", Until: "2011-12-30"}, loc)
	require.Error(t, err)
}

func TestReportCommandsRejectExplicitInvalidTimezone(t *testing.T) {
	for _, zone := range []string{"", "Local", "EST", "CET", "GMT", "EST5EDT", "+05:30"} {
		t.Run(zone, func(t *testing.T) {
			for _, cmd := range []*cobra.Command{newUsageDailyCommand(), newActivityReportCommand(), newStatsCommand()} {
				cmd.SetArgs([]string{"--timezone=" + zone})
				err := cmd.ExecuteContext(t.Context())
				require.Error(t, err)
				assert.Contains(t, err.Error(), "timezone")
			}
		})
	}
}

func TestFrictionTimezoneEnvironmentIsExplicit(t *testing.T) {
	database := dbtest.OpenTestDB(t)
	cfg := config.Config{Friction: config.FrictionConfig{Enabled: true, Timezone: "UTC", BackfillDays: 7}}
	for _, zone := range []string{"", "Local", "EST", "GMT", "+05:30"} {
		t.Run(zone, func(t *testing.T) {
			t.Setenv("AGENTSVIEW_FRICTION_TZ", zone)
			_, err := newFrictionRunner(cfg, database, time.Now)
			require.Error(t, err)
		})
	}
	// A saved abbreviation remains usable during the one-release warning period.
	t.Setenv("AGENTSVIEW_FRICTION_TZ", "")
	require.NoError(t, os.Unsetenv("AGENTSVIEW_FRICTION_TZ"))
	cfg.Friction.Timezone = "EST"
	runner, err := newFrictionRunner(cfg, database, time.Now)
	require.NoError(t, err)
	assert.Equal(t, "EST", runner.Loc.String())
}
