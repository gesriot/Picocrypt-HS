package ui

import (
	"os"
	"testing"

	"Picocrypt-NG/internal/app"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

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

// asciiWarmup is every printable-ASCII rune (0x20..0x7e). Measuring it populates
// one cmapCache bucket per rune&0xFF; since printable ASCII has distinct low
// bytes, warming it covers every bucket the Latin UI text in these tests can
// touch, so later measurements only read warmed buckets.
func asciiWarmup() string {
	b := make([]byte, 0, 0x7e-0x20+1)
	for c := byte(0x20); c <= 0x7e; c++ {
		b = append(b, c)
	}
	return string(b)
}

// TestMain pre-warms Fyne's process-global font Face cache before any test
// measures text. The Face's cmapCache is a lock-free [256]uint32 keyed by
// rune&0xFF (go-text typesetting cmap_cache.go) shared across every
// test.NewApp; a first-write racing a concurrent read trips the -race detector
// (the CI amd64 matrix). MeasureText and the harfbuzz shaping path used by
// Entry/RichText both populate it via Face.NominalGlyph, so warming via
// MeasureText covers both readers.
//
// The warmup must COMPLETE before m.Run starts. fyne.DoAndWait only blocks when
// called off the main goroutine: the test driver's EnsureNotMain runs the func
// inline when off-main, but on the main goroutine (where TestMain runs) it logs
// a thread violation and fires the func on a new, un-awaited goroutine — which
// leaves the warmup racing the first test (the exact G14-vs-G15 stack the
// -race job reported). Running the warmup from a child goroutine forces the
// synchronous inline path; <-done then guarantees it finished before any test.
func TestMain(m *testing.M) {
	app := test.NewApp()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fyne.DoAndWait(func() {
			ascii := asciiWarmup()
			_ = fyne.MeasureText(ascii, 14, fyne.TextStyle{})
			_ = fyne.MeasureText(ascii, 14, fyne.TextStyle{Bold: true})
		})
	}()
	<-done
	app.Quit()
	os.Exit(m.Run())
}

func newTestFyneApp(t *testing.T) fyne.App {
	t.Helper()

	app := test.NewApp()
	t.Cleanup(func() {
		fyne.DoAndWait(func() {})
		app.Quit()
	})
	return app
}
