package db

import (
	"context"
	"fmt"
	"strings"
)

// MessageScopeFilter adapts analytics model and time filters for message reduction.
func (f AnalyticsFilter) MessageScopeFilter() ScopeFilter {
	models := make(map[string]struct{})
	for _, m := range CSVFilterValues(f.Model) {
		models[m] = struct{}{}
	}
	return ScopeFilter{
		Models:    models,
		DayOfWeek: f.DayOfWeek,
		Hour:      f.Hour,
	}
}

// MessageScope groups model-matched messages by session. Nil means no model filter.
type MessageScope map[string][]ScopedMessage

// UniqueAnalyticsIDs returns IDs in first-seen order, including a non-nil empty result.
func UniqueAnalyticsIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	return unique
}

// resolveAnalyticsMessageScope streams candidate messages for sessionIDs and
// reduces them to the model/time-matched set. It returns nil when no model
// filter is set, signalling the caller to keep its session-grain path.
// includeContent omits the (expensive) content column for count-only panels.
func (db *DB) resolveAnalyticsMessageScope(
	ctx context.Context,
	sessionIDs []string,
	f AnalyticsFilter,
	includeContent bool,
) (MessageScope, error) {
	if strings.TrimSpace(f.Model) == "" {
		return nil, nil
	}

	unique := UniqueAnalyticsIDs(sessionIDs)

	flt := f.MessageScopeFilter()
	loc := f.location()
	bySession := make(MessageScope, len(unique))
	emit := func(m ScopedMessage) {
		bySession[m.SessionID] = append(bySession[m.SessionID], m)
	}

	contentExpr := "''"
	if includeContent {
		contentExpr = "content"
	}

	if err := queryChunked(unique, func(chunk []string) error {
		reducer := NewScopeReducer(flt, emit)
		ph, args := InPlaceholders(chunk)
		rows, err := db.getReader().QueryContext(ctx, `
			SELECT session_id, ordinal, role, source_subtype, is_system, model,
				has_thinking, has_tool_use, COALESCE(timestamp, ''),
				output_tokens, has_output_tokens, content_length, `+contentExpr+`
			FROM messages
			WHERE session_id IN `+ph+`
			ORDER BY session_id, ordinal`,
			args...,
		)
		if err != nil {
			return fmt.Errorf("querying analytics candidate messages: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				sessionID, role, sourceSubtype, model, ts, content string
				ordinal, outputTokens, contentLength               int
				isSystem, hasThinking, hasToolUse, hasOutputTokens bool
			)
			if err := rows.Scan(
				&sessionID, &ordinal, &role, &sourceSubtype, &isSystem, &model,
				&hasThinking, &hasToolUse, &ts, &outputTokens,
				&hasOutputTokens, &contentLength, &content,
			); err != nil {
				return fmt.Errorf("scanning analytics candidate message: %w", err)
			}
			parsed, has := LocalTime(ts, loc)
			if err := reducer.Push(MessageInput{
				SessionID:       sessionID,
				Ordinal:         ordinal,
				Role:            role,
				SourceSubtype:   sourceSubtype,
				Model:           model,
				IsSystem:        isSystem,
				Timestamp:       ts,
				LocalTime:       parsed,
				HasLocalTime:    has,
				HasThinking:     hasThinking,
				HasToolUse:      hasToolUse,
				OutputTokens:    outputTokens,
				HasOutputTokens: hasOutputTokens,
				ContentLength:   contentLength,
				Content:         content,
			}); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterating analytics candidate messages: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return bySession, nil
}

// StatsBySession aggregates matched rows per session.
func (s MessageScope) StatsBySession() map[string]MessageStats {
	out := make(map[string]MessageStats, len(s))
	for id, rows := range s {
		out[id] = ScopeStats(rows)
	}
	return out
}

// addFederationAnalyticsStats keeps summary counts at session grain while
// selecting token totals from the matching federation usage events.
func (db *DB) addFederationAnalyticsStats(ctx context.Context, ids []string, f AnalyticsFilter, stats map[string]MessageStats) error {
	models := f.MessageScopeFilter().Models
	return queryChunked(UniqueAnalyticsIDs(ids), func(chunk []string) error {
		ph, args := InPlaceholders(chunk)
		rows, err := db.getReader().QueryContext(ctx, `SELECT s.id,s.message_count,s.user_message_count,COALESCE(s.started_at,''),u.model,u.output_tokens FROM sessions s JOIN usage_events u ON u.session_id=s.id WHERE u.source='federation' AND s.id IN `+ph, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, start, model string
			var messages, users, output int
			if err := rows.Scan(&id, &messages, &users, &start, &model, &output); err != nil {
				return err
			}
			if len(models) > 0 {
				if _, ok := models[model]; !ok {
					continue
				}
			}
			if f.HasTimeFilter() {
				local, ok := LocalTime(start, f.location())
				if !ok || !f.matchesTimeFilter(local) {
					continue
				}
			}
			stat := stats[id]
			stat.Messages, stat.UserMessages = messages, users
			if output > 0 {
				stat.OutputTokens += output
				stat.HasOutputTokens = true
			}
			stats[id] = stat
		}
		return rows.Err()
	})
}

// TimingBySession projects matched rows into the velocity timing view.
func (s MessageScope) TimingBySession() map[string][]TimingMessage {
	out := make(map[string][]TimingMessage, len(s))
	for id, rows := range s {
		out[id] = ScopeTiming(rows)
	}
	return out
}
