package ui

import (
	"context"
	"sync"
	"sync/atomic"
)

// workerLifecycle owns application workers and makes registration atomic with
// the transition to shutdown.
type workerLifecycle struct {
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	stopping atomic.Bool
	workers  sync.WaitGroup
}

type workerReservation struct {
	owner     *workerLifecycle
	completed atomic.Bool
}

func newWorkerLifecycle() *workerLifecycle {
	ctx, cancel := context.WithCancel(context.Background())
	return &workerLifecycle{ctx: ctx, cancel: cancel}
}

func (l *workerLifecycle) reserve() (*workerReservation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopping.Load() {
		return nil, false
	}

	l.workers.Add(1)
	return &workerReservation{owner: l}, true
}

func (r *workerReservation) launch(fn func(context.Context)) {
	if !r.completed.CompareAndSwap(false, true) {
		panic("ui: worker reservation completed more than once")
	}

	go func() {
		defer r.owner.workers.Done()
		fn(r.owner.ctx)
	}()
}

func (r *workerReservation) release() {
	if !r.completed.CompareAndSwap(false, true) {
		panic("ui: worker reservation completed more than once")
	}
	r.owner.workers.Done()
}

func (l *workerLifecycle) beginStop() bool {
	l.mu.Lock()
	if l.stopping.Load() {
		l.mu.Unlock()
		return false
	}
	l.stopping.Store(true)
	l.mu.Unlock()

	l.cancel()
	return true
}

func (l *workerLifecycle) wait() {
	l.workers.Wait()
}

func (l *workerLifecycle) isStopping() bool {
	return l.stopping.Load()
}
