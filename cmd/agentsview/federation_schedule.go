package main

import (
	"context"
	"time"

	"go.kenn.io/agentsview/internal/federation"
	"go.kenn.io/agentsview/internal/poller"
)

func federationPushJob(service *federation.Service) poller.Job {
	return poller.Job{Name: "federation-push", Interval: 15 * time.Minute, RunAtStart: true, Run: func(ctx context.Context) error { _, err := service.Push(ctx); return err }}
}
