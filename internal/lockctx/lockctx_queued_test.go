package lockctx

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Cancel immediately after observing Err, before the caller can acquire mu.
// This models cancellation between checking the context and granting ownership.
type cancelAfterErr struct {
	context.Context
	cancel context.CancelFunc
}

func (c cancelAfterErr) Err() error {
	err := c.Context.Err()
	c.cancel()
	return err
}

func TestLockQueuedCancellationAtAcquisition(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var mu sync.Mutex
	var waiter Waiter
	err := LockQueued(cancelAfterErr{ctx, cancel}, &mu, &waiter)
	if err == nil {
		mu.Unlock()
	}
	require.ErrorIs(t, err, context.Canceled)
	require.Eventually(t, mu.TryLock, 10*time.Second, 5*time.Millisecond, "canceled acquisition must release the mutex")
	mu.Unlock()
}

func TestLockQueuedOrdersSurvivors(t *testing.T) {
	for _, cancelMiddle := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel-middle=%v", cancelMiddle), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			var mu sync.Mutex
			var waiter Waiter
			mu.Lock()
			releaseInitial := sync.OnceFunc(mu.Unlock)
			defer releaseInitial()
			order := make(chan int, 3)
			releases := []chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{})}
			done := make([]chan error, 3)
			middle, stopMiddle := context.WithCancel(ctx)
			defer stopMiddle()
			for i := range 3 {
				done[i] = make(chan error, 1)
				waitCtx := ctx
				if i == 1 {
					waitCtx = middle
				}
				go func() {
					err := LockQueued(waitCtx, &mu, &waiter)
					if err == nil {
						order <- i
						select {
						case <-releases[i]:
						case <-ctx.Done():
						}
						mu.Unlock()
					}
					done[i] <- err
				}()
				require.Eventually(t, func() bool { waiter.guard.Lock(); defer waiter.guard.Unlock(); return waiter.waiting.Len() == i+1 }, 10*time.Second, 5*time.Millisecond)
			}
			expected := []int{0, 1, 2}
			if cancelMiddle {
				stopMiddle()
				require.ErrorIs(t, <-done[1], context.Canceled)
				expected = []int{0, 2}
			}
			releaseInitial()
			for _, want := range expected {
				select {
				case got := <-order:
					require.Equal(t, want, got)
					close(releases[want])
				case <-ctx.Done():
					require.NoError(t, ctx.Err())
				}
				require.NoError(t, <-done[want])
			}
		})
	}
}
