package main

import (
	"context"
	"time"

	"go.kenn.io/agentsview/internal/federation"
	"go.kenn.io/agentsview/internal/poller"
)

func federationPushJob(service *federation.Service) poller.Job {
	return newFederationPushJob(func(ctx context.Context, full bool) error {
		_, err := service.PushScheduled(ctx, full)
		return err
	}, time.Now)
}

func newFederationPushJob(push func(context.Context, bool) error, now func() time.Time) poller.Job {
	var lastFull time.Time
	return poller.Job{Name: "federation-push", Interval: 15 * time.Minute, RunAtStart: true, Run: func(ctx context.Context) error {
		started := now()
		full := lastFull.IsZero() || started.Sub(lastFull) >= time.Hour
		bounded, cancel := context.WithTimeout(ctx, 14*time.Minute)
		defer cancel()
		if err := push(bounded, full); err != nil {
			return err
		}
		if full {
			lastFull = started
		}
		return nil
	}}
}
