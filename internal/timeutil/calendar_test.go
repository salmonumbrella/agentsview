package timeutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTimezoneParameterPolicy(t *testing.T) {
	for _, name := range []string{"", "Local", "EST", "CET", "GMT", "EST5EDT", "+05:30", "-0400", " UTC ", "Mars/Olympus", "posix/America/New_York", "right/America/New_York"} {
		t.Run(name, func(t *testing.T) { _, err := LoadTimezone(name); require.Error(t, err) })
	}
	for _, name := range []string{"UTC", "America/Santiago", "America/Havana", "Etc/GMT+5", "Asia/Kathmandu"} {
		t.Run(name, func(t *testing.T) {
			loc, err := LoadTimezone(name)
			require.NoError(t, err)
			assert.Equal(t, name, loc.String())
		})
	}
}

func TestReportDateAgreesWithDayBoundsAcrossRollback(t *testing.T) {
	for _, tc := range []struct{ zone, at, want string }{
		{"America/St_Johns", "2010-11-07T02:29:59Z", "2010-11-06"},
		{"America/St_Johns", "2010-11-07T02:30:00Z", "2010-11-07"},
		{"America/St_Johns", "2010-11-07T02:45:00Z", "2010-11-07"},
		{"America/Goose_Bay", "2010-11-07T03:15:00Z", "2010-11-07"},
		{"Antarctica/Casey", "2010-03-04T15:30:00Z", "2010-03-05"},
		{"Pacific/Apia", "2011-12-30T10:00:00Z", "2011-12-31"},
		{"Asia/Jerusalem", "2000-10-05T22:30:00Z", "2000-10-06"},
	} {
		t.Run(tc.zone+tc.at, func(t *testing.T) {
			loc, err := LoadTimezone(tc.zone)
			require.NoError(t, err)
			at, err := time.Parse(time.RFC3339, tc.at)
			require.NoError(t, err)
			got := ReportDate(at, loc).String()
			assert.Equal(t, tc.want, got)
			start, end, err := DateBounds(got, loc)
			require.NoError(t, err)
			assert.False(t, at.Before(start))
			assert.True(t, at.Before(end))
		})
	}
}

func TestParseSinceDateUsesFirstRealInstant(t *testing.T) {
	loc, err := LoadTimezone("America/Santiago")
	require.NoError(t, err)
	got, err := ParseSince(time.Date(2026, 9, 8, 12, 0, 0, 0, loc), "2026-09-06")
	require.NoError(t, err)
	assert.Equal(t, "2026-09-06T04:00:00Z", got.UTC().Format(time.RFC3339))
}
