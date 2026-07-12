package ui

import (
	"sync"
	"testing"

	"Picocrypt-NG/internal/app"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

// fyneTestDispatcher serializes callbacks in the same FIFO order as the
// production driver. Synchronous callbacks stay on their caller goroutine so
// assertions inside existing DoAndWait callbacks retain testing.T semantics;
// asynchronous callbacks run in short-lived goroutines after their turn starts.
type fyneTestDispatcher struct {
	mu      sync.Mutex
	ready   *sync.Cond
	next    uint64
	serving uint64
}

func newFyneTestDispatcher() *fyneTestDispatcher {
	d := &fyneTestDispatcher{}
	d.ready = sync.NewCond(&d.mu)
	return d
}

func (d *fyneTestDispatcher) dispatch(fn func(), wait bool) {
	d.mu.Lock()
	ticket := d.next
	d.next++
	d.mu.Unlock()

	run := func() {
		d.mu.Lock()
		for ticket != d.serving {
			d.ready.Wait()
		}
		d.mu.Unlock()

		defer d.finish()
		fn()
	}
	if wait {
		run()
		return
	}

	go run()
}

func (d *fyneTestDispatcher) finish() {
	d.mu.Lock()
	d.serving++
	d.ready.Broadcast()
	d.mu.Unlock()
}

var testFyneDispatcher = newFyneTestDispatcher()

type dispatchedTestApp struct {
	fyne.App
	driver fyne.Driver
}

func (a *dispatchedTestApp) Driver() fyne.Driver {
	return a.driver
}

type dispatchedTestDriver struct {
	fyne.Driver
}

func (d *dispatchedTestDriver) DoFromGoroutine(fn func(), wait bool) {
	testFyneDispatcher.dispatch(fn, wait)
}

// mustNewState builds an *app.State for UI tests, failing the test if RS-codec
// initialization returns an error. Centralizes the (*State, error) call after
// APP-01 changed app.NewState's signature, keeping the many call sites terse.
func mustNewState(t *testing.T) *app.State {
	t.Helper()
	s, err := app.NewState()
	if err != nil {
		t.Fatalf("app.NewState() returned error: %v", err)
	}
	return s
}

func newTestFyneApp(t *testing.T) fyne.App {
	t.Helper()

	var app fyne.App
	testFyneDispatcher.dispatch(func() {
		raw := test.NewApp()
		app = &dispatchedTestApp{
			App: raw,
			driver: &dispatchedTestDriver{
				Driver: raw.Driver(),
			},
		}
		fyne.SetCurrentApp(app)
	}, true)
	t.Cleanup(func() {
		testFyneDispatcher.dispatch(app.Quit, true)
	})
	return app
}
