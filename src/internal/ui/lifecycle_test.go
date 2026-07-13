package ui

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"fyne.io/fyne/v2"
)

func TestWorkerGroupStopWaitsForReservedWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		workers := newWorkerLifecycle()
		reservation, ok := workers.reserve()
		if !ok {
			t.Fatal("initial worker reservation was rejected")
		}

		if !workers.beginStop() {
			t.Fatal("first stop request was rejected")
		}
		if _, ok := workers.reserve(); ok {
			t.Fatal("worker reservation succeeded after shutdown began")
		}

		waitReturned := make(chan struct{})
		go func() {
			workers.wait()
			close(waitReturned)
		}()
		synctest.Wait()

		select {
		case <-waitReturned:
			t.Fatal("worker wait returned before the accepted reservation was completed")
		default:
		}

		workerSawCancellation := make(chan bool, 1)
		reservation.launch(func(ctx context.Context) {
			workerSawCancellation <- ctx.Err() != nil
		})
		synctest.Wait()

		if !<-workerSawCancellation {
			t.Fatal("worker launched after stop did not inherit the cancelled lifecycle context")
		}
		select {
		case <-waitReturned:
		default:
			t.Fatal("worker wait did not return after the accepted reservation completed")
		}
	})
}

func TestOrderlyShutdownWaitsForAcceptedOpenedPathCallback(t *testing.T) {
	resetOpenedPathsForTest(t)
	fyneApp := newTestFyneApp(t)

	a, err := NewApp("test")
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	a.fyneApp = fyneApp
	a.Window = fyneApp.NewWindow("shutdown-test")

	closed := make(chan struct{})
	a.Window.SetOnClosed(func() {
		close(closed)
	})

	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	setOpenedPathsNotify(func() {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
	})

	openedPathsMu.Lock()
	generation := openedPathsGeneration
	openedPathsMu.Unlock()
	notifyReturned := make(chan struct{})
	go func() {
		notifyOpenedPaths(generation)
		close(notifyReturned)
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the opened-path callback to start")
	}

	fyne.DoAndWait(a.beginOrderlyShutdown)
	workersDone := a.workersDone
	fyne.DoAndWait(a.shutdownSentinelTick)
	select {
	case <-closed:
		t.Fatal("window closed while an accepted opened-path callback was still running")
	default:
	}

	close(release)
	select {
	case <-notifyReturned:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the opened-path callback to return")
	}
	select {
	case <-workersDone:
	case <-time.After(time.Second):
		t.Fatal("orderly shutdown did not finish after the accepted callback returned")
	}

	setOpenedPathsNotify(func() {
		calls.Add(1)
	})
	appendOpenedPath("/tmp/post-stop.txt")
	flushOpenedPaths()
	openedPathsMu.Lock()
	postStopGeneration := openedPathsGeneration
	openedPathsMu.Unlock()
	notifyOpenedPaths(postStopGeneration)
	if got := calls.Load(); got != 1 {
		t.Fatalf("opened-path handler calls after shutdown = %d; want no call after the accepted callback", got-1)
	}

	fyne.DoAndWait(a.shutdownSentinelTick)
	select {
	case <-closed:
	default:
		t.Fatal("window remained open after all accepted callbacks and workers completed")
	}
}
