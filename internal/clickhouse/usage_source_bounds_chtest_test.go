//go:build chtest

package clickhouse

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/storage"
)

// Filtering before the session join must retain fallback timestamps and the
// full local day, and must not resurrect a replaced timestamp.
func TestDailyUsageSourceBounds(t *testing.T) {
	t.Parallel()
	store, _, _ := newPushedStore(t)
	ctx := t.Context()
	_, err := store.DB().ExecContext(ctx, "SYSTEM STOP MERGES messages")
	require.NoError(t, err)
	const id = "source-bounds"
	_, err = store.DB().ExecContext(ctx, `INSERT INTO sessions
	 (id,project,agent,started_at,message_count,user_message_count,push_version)
	 VALUES (?, 'source-bounds', 'claude', toDateTime64('2026-03-08 12:00:00',6,'UTC'), 6, 3, 1)`, id)
	require.NoError(t, err)
	for ordinal, stamp := range []string{
		"",
		"2026-03-08 04:59:59.999999",
		"2026-03-08 05:00:00",
		"2026-03-09 03:59:59.999999",
		"2026-03-09 04:00:00",
		"2026-03-08 12:01:00",
	} {
		_, err = store.DB().ExecContext(ctx, `INSERT INTO messages
		 (session_id,ordinal,role,timestamp,model,token_usage,push_version)
		 VALUES (?,?,'assistant',parseDateTime64BestEffortOrNull(?,6,'UTC'),'gpt-4o',?,1)`,
			id, ordinal, stamp, fmt.Sprintf(`{"output_tokens":%d}`, ordinal+1))
		require.NoError(t, err)
	}
	_, err = store.DB().ExecContext(ctx, `INSERT INTO messages
	 (session_id,ordinal,role,timestamp,model,token_usage,push_version)
	 VALUES (?,5,'assistant',toDateTime64('2026-04-08 12:01:00',6,'UTC'),'gpt-4o',?,2)`, id, `{"output_tokens":6}`)
	require.NoError(t, err)
	got, err := store.GetDailyUsage(ctx, db.UsageFilter{
		From: "2026-03-08", To: "2026-03-08", Timezone: "America/New_York",
		Project: "source-bounds", Agent: "claude",
	})
	require.NoError(t, err)
	require.Equal(t, 8, got.Totals.OutputTokens)
}

func TestFederationAggregateUsageIsNotClamped(t *testing.T) {
	ctx := t.Context()
	local, target := seedFixture(t)
	stamp := "2026-03-08T12:00:00Z"
	input := db.MaxPlausibleTokens + 250_000
	_, err := local.WriteSessionBatchAtomic(ctx, []db.SessionBatchWrite{{
		Session:     db.Session{ID: "federation-aggregate", Project: "federation", Machine: "federated", Agent: "claude", StartedAt: &stamp, MessageCount: 2, UserMessageCount: 1},
		UsageEvents: []db.UsageEvent{{Source: "federation", Model: "model", InputTokens: input, OccurredAt: stamp, DedupKey: "model"}},
		DataVersion: 1,
	}})
	require.NoError(t, err)
	syncer := newTestSync(t, local, target, storage.PusherOptions{})
	_, err = syncer.Push(ctx, false, nil)
	require.NoError(t, err)
	store, err := NewStore(ctx, target)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	result, err := store.GetDailyUsage(ctx, db.UsageFilter{From: "2026-03-08", To: "2026-03-08", Timezone: "UTC", Project: "federation"})
	require.NoError(t, err)
	require.Equal(t, input, result.Totals.InputTokens)
}
