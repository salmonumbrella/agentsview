package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.kenn.io/agentsview/internal/db"
)

func TestReportQueryRejectsExplicitInvalidTimezone(t *testing.T) {
	srv := testServer(t, 0)
	for _, path := range []string{"/api/v1/activity/report", "/api/v1/analytics/summary", "/api/v1/usage/summary", "/api/v1/sessions"} {
		for _, zone := range []string{"", "Local", "EST", "CET", "GMT", "EST5EDT", "+05:30"} {
			t.Run(path+zone, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, path+"?timezone="+url.QueryEscape(zone), nil)
				req.Host = "127.0.0.1:0"
				req.RemoteAddr = "127.0.0.1:12345"
				w := httptest.NewRecorder()
				srv.Handler().ServeHTTP(w, req)
				assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
				assert.Contains(t, w.Body.String(), "timezone")
			})
		}
	}
}

func TestInsightRejectsExplicitInvalidTimezone(t *testing.T) {
	srv := testServer(t, 0)
	for _, zone := range []any{"", "Local", "EST", "GMT", "+05:30", nil} {
		for _, nested := range []bool{false, true} {
			body := map[string]any{"type": "daily_activity", "date_from": "2026-09-06", "date_to": "2026-09-06"}
			if nested {
				body["filters"] = map[string]any{"timezone": zone}
			} else {
				body["timezone"] = zone
			}
			w := serveJSON(t, srv.Handler(), http.MethodPost, "/api/v1/insights/generate", body)
			assert.GreaterOrEqual(t, w.Code, 400, w.Body.String())
			assert.Less(t, w.Code, 500, w.Body.String())
			assert.Contains(t, w.Body.String(), "timezone")
		}
	}
}

func TestCannedCoachBoundsAcrossMidnightGap(t *testing.T) {
	loc, err := time.LoadLocation("America/Santiago")
	require.NoError(t, err)
	from, to := cannedCoachUTCDateBounds("2026-09-06", "2026-09-06", loc)
	assert.Equal(t, "2026-09-06", from)
	assert.Equal(t, "2026-09-07", to)
	assert.False(t, cannedCoachSessionInDateRange(db.Session{CreatedAt: "2026-09-06T03:30:00Z"}, "2026-09-06", "2026-09-06", loc))
	assert.True(t, cannedCoachSessionInDateRange(db.Session{CreatedAt: "2026-09-06T04:00:00Z"}, "2026-09-06", "2026-09-06", loc))
	apia, err := time.LoadLocation("Pacific/Apia")
	require.NoError(t, err)
	from, to = cannedCoachUTCDateBounds("2011-12-30", "2011-12-30", apia)
	assert.Equal(t, "2011-12-30", from)
	assert.Equal(t, "2011-12-30", to)
}

func TestActivityRangeSummarySkipsMissingMidnightGap(t *testing.T) {
	srv := testServer(t, 0)
	for _, row := range []struct{ id, at string }{
		{"previous", "2026-09-06T03:30:00Z"},
		{"current", "2026-09-06T04:00:00Z"},
		{"late", "2026-09-07T02:30:00Z"},
	} {
		require.NoError(t, srv.db.UpsertSession(t.Context(), db.Session{ID: row.id, Project: "p", Machine: "test", Agent: "claude", StartedAt: &row.at, EndedAt: &row.at, MessageCount: 1, RelationshipType: "root", DataVersion: 1}))
		require.NoError(t, srv.db.ReplaceSessionMessages(t.Context(), row.id, []db.Message{{SessionID: row.id, Ordinal: 0, Role: "assistant", Content: "x", Timestamp: row.at, Model: "m1"}}))
	}
	summary, err := srv.activityRangeSummary(t.Context(), generateInsightRequest{Type: "daily_activity", DateFrom: "2026-09-06", DateTo: "2026-09-06", Timezone: "America/Santiago"})
	require.NoError(t, err)
	require.NotNil(t, summary)
	assert.Equal(t, 2, summary.Sessions, "exclude yesterday's 23:30 and include today's final hour")
}
