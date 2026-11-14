package timeutil

import (
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/civil"
	"go.kenn.io/kit/civiltime"
)

// LoadTimezone validates an explicit report timezone. Defaults belong to the
// caller: an empty value, Local, numeric offsets and abbreviations are not zones.
func LoadTimezone(name string) (*time.Location, error) {
	if (name != "UTC" && !strings.Contains(name, "/")) ||
		strings.HasPrefix(name, "posix/") || strings.HasPrefix(name, "right/") {
		return nil, fmt.Errorf("invalid timezone %q: use UTC or an IANA name such as America/New_York", name)
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("invalid timezone %q: %w", name, err)
	}
	return loc, nil
}

// DateBounds parses a calendar date without first assigning it a wall clock.
// Skipped dates have an empty interval at the next existing day's start.
func DateBounds(date string, loc *time.Location) (time.Time, time.Time, error) {
	d, err := civil.ParseDate(date)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	start, end, _ := civiltime.DayBounds(d, loc)
	return start, end, nil
}

// ReportDate places an instant in the same half-open day as DateBounds. When a
// clock rolls back across midnight, the wall calendar can briefly show yesterday
// after today's interval has begun. Such instants still belong to today's report.
func ReportDate(at time.Time, loc *time.Location) civil.Date {
	if loc == nil {
		loc = time.UTC
	}
	local := at.In(loc)
	date := civil.DateOf(local)
	// Most instants need no boundary calculation. A rollback can only matter
	// while the date is earlier than it was immediately before this zone regime.
	if start, _ := local.ZoneBounds(); !start.IsZero() {
		previous := civil.DateOf(start.Add(-time.Nanosecond).In(loc))
		if previous.After(date) {
			_, end, _ := civiltime.DayBounds(date, loc)
			for !at.Before(end) {
				date = date.AddDays(1)
				_, end, _ = civiltime.DayBounds(date, loc)
			}
		}
	}
	return date
}
