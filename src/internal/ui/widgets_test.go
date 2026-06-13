// Package ui provides tests for custom Fyne widgets.
package ui

import (
	"image/color"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	fynetheme "fyne.io/fyne/v2/theme"
)

// TestPasswordStrengthIndicator tests the password strength indicator widget.
func TestPasswordStrengthIndicator(t *testing.T) {
	// Create test app
	newTestFyneApp(t)

	t.Run("NewPasswordStrengthIndicator", func(t *testing.T) {
		indicator := NewPasswordStrengthIndicator()
		if indicator == nil {
			t.Fatal("Expected non-nil indicator")
		}
	})

	t.Run("SetStrength", func(t *testing.T) {
		indicator := NewPasswordStrengthIndicator()

		// Test all strength levels
		for strength := 0; strength <= 4; strength++ {
			indicator.SetStrength(strength)
			if indicator.strength != strength {
				t.Errorf("Expected strength %d, got %d", strength, indicator.strength)
			}
		}
	})

	t.Run("SetVisible", func(t *testing.T) {
		indicator := NewPasswordStrengthIndicator()

		indicator.SetVisible(true)
		if !indicator.visible {
			t.Error("Expected visible to be true")
		}

		indicator.SetVisible(false)
		if indicator.visible {
			t.Error("Expected visible to be false")
		}
	})

	t.Run("SetDecryptMode", func(t *testing.T) {
		indicator := NewPasswordStrengthIndicator()

		indicator.SetDecryptMode(true)
		if !indicator.decryMode {
			t.Error("Expected decryMode to be true")
		}

		indicator.SetDecryptMode(false)
		if indicator.decryMode {
			t.Error("Expected decryMode to be false")
		}
	})

	t.Run("MinSize", func(t *testing.T) {
		indicator := NewPasswordStrengthIndicator()
		minSize := indicator.MinSize()

		if minSize.Width != 24 {
			t.Errorf("Expected width 24, got %f", minSize.Width)
		}
		if minSize.Height != 24 {
			t.Errorf("Expected height 24, got %f", minSize.Height)
		}
	})

	t.Run("CreateRenderer", func(t *testing.T) {
		indicator := NewPasswordStrengthIndicator()
		renderer := indicator.CreateRenderer()

		if renderer == nil {
			t.Fatal("Expected non-nil renderer")
		}

		objects := renderer.Objects()
		// Uses single canvas.Arc instead of 36 line segments for efficient rendering
		if len(objects) != 1 {
			t.Errorf("Expected 1 canvas object (Arc), got %d", len(objects))
		}
	})
}

// TestValidationIndicator tests the validation indicator widget.
func TestValidationIndicator(t *testing.T) {
	newTestFyneApp(t)

	t.Run("NewValidationIndicator", func(t *testing.T) {
		indicator := NewValidationIndicator()
		if indicator == nil {
			t.Fatal("Expected non-nil indicator")
		}
	})

	t.Run("SetValid", func(t *testing.T) {
		indicator := NewValidationIndicator()

		indicator.SetValid(true)
		if !indicator.valid {
			t.Error("Expected valid to be true")
		}

		indicator.SetValid(false)
		if indicator.valid {
			t.Error("Expected valid to be false")
		}
	})

	t.Run("SetVisible", func(t *testing.T) {
		indicator := NewValidationIndicator()

		indicator.SetVisible(true)
		if !indicator.visible {
			t.Error("Expected visible to be true")
		}

		indicator.SetVisible(false)
		if indicator.visible {
			t.Error("Expected visible to be false")
		}
	})

	t.Run("MinSize", func(t *testing.T) {
		indicator := NewValidationIndicator()
		minSize := indicator.MinSize()

		if minSize.Width != 24 {
			t.Errorf("Expected width 24, got %f", minSize.Width)
		}
		if minSize.Height != 24 {
			t.Errorf("Expected height 24, got %f", minSize.Height)
		}
	})

	t.Run("CreateRenderer", func(t *testing.T) {
		indicator := NewValidationIndicator()
		renderer := indicator.CreateRenderer()

		if renderer == nil {
			t.Fatal("Expected non-nil renderer")
		}

		objects := renderer.Objects()
		// Uses single canvas.Circle instead of 24 line segments for efficient rendering
		if len(objects) != 1 {
			t.Errorf("Expected 1 canvas object (Circle), got %d", len(objects))
		}
	})
}

// TestPasswordEntry tests the password entry widget.
func TestPasswordEntry(t *testing.T) {
	newTestFyneApp(t)

	t.Run("NewPasswordEntry", func(t *testing.T) {
		entry := NewPasswordEntry()
		if entry == nil {
			t.Fatal("Expected non-nil entry")
		}

		// Should start hidden (password mode)
		if !entry.hidden {
			t.Error("Expected hidden to be true initially")
		}
		if !entry.Password {
			t.Error("Expected Password mode to be true initially")
		}
	})

	t.Run("SetHidden", func(t *testing.T) {
		entry := NewPasswordEntry()

		entry.SetHidden(false)
		if entry.hidden {
			t.Error("Expected hidden to be false")
		}
		if entry.Password {
			t.Error("Expected Password mode to be false")
		}

		entry.SetHidden(true)
		if !entry.hidden {
			t.Error("Expected hidden to be true")
		}
		if !entry.Password {
			t.Error("Expected Password mode to be true")
		}
	})

	t.Run("IsHidden", func(t *testing.T) {
		entry := NewPasswordEntry()

		if !entry.IsHidden() {
			t.Error("Expected IsHidden() to return true initially")
		}

		entry.SetHidden(false)
		if entry.IsHidden() {
			t.Error("Expected IsHidden() to return false")
		}
	})
}

// TestColoredLabel tests the colored label widget.
func TestColoredLabel(t *testing.T) {
	newTestFyneApp(t)

	t.Run("NewColoredLabel", func(t *testing.T) {
		testColor := color.RGBA{R: 255, G: 0, B: 0, A: 255}
		label := NewColoredLabel("Test", testColor)

		if label == nil {
			t.Fatal("Expected non-nil label")
		}
		if label.text != "Test" {
			t.Errorf("Expected text 'Test', got '%s'", label.text)
		}
	})

	t.Run("SetText", func(t *testing.T) {
		label := NewColoredLabel("Initial", color.White)

		label.SetText("Updated")
		if label.text != "Updated" {
			t.Errorf("Expected text 'Updated', got '%s'", label.text)
		}
	})

	t.Run("SetColor", func(t *testing.T) {
		label := NewColoredLabel("Test", color.White)
		newColor := color.RGBA{R: 0, G: 255, B: 0, A: 255}

		label.SetColor(newColor)
		if label.color != newColor {
			t.Error("Expected color to be updated")
		}
	})

	t.Run("MinSize", func(t *testing.T) {
		label := NewColoredLabel("Test", color.White)
		minSize := label.MinSize()

		// Width/height must equal the measured text size at the theme text size.
		want := fyne.MeasureText("Test", fynetheme.TextSize(), fyne.TextStyle{})
		if minSize.Width != want.Width {
			t.Errorf("Expected width %f, got %f", want.Width, minSize.Width)
		}
		if minSize.Height != want.Height {
			t.Errorf("Expected height %f, got %f", want.Height, minSize.Height)
		}
	})

	t.Run("MinSize_TruncationCap", func(t *testing.T) {
		// Default truncation is ellipsis (see NewColoredLabel), so a long string
		// must be capped at 600px to avoid forcing window resizing.
		long := strings.Repeat("A", 500)
		raw := fyne.MeasureText(long, fynetheme.TextSize(), fyne.TextStyle{})
		if raw.Width <= 600 {
			t.Fatalf("precondition: long string must exceed 600px, got %f", raw.Width)
		}
		label := NewColoredLabel(long, color.White)
		if got := label.MinSize().Width; got != 600 {
			t.Errorf("Expected capped width 600, got %f", got)
		}
	})

	t.Run("CreateRenderer", func(t *testing.T) {
		label := NewColoredLabel("Test", color.White)
		renderer := label.CreateRenderer()

		if renderer == nil {
			t.Fatal("Expected non-nil renderer")
		}

		objects := renderer.Objects()
		if len(objects) != 1 {
			t.Errorf("Expected 1 object, got %d", len(objects))
		}
	})
}

// TestDisabledEntry tests the disabled entry widget.
func TestDisabledEntry(t *testing.T) {
	newTestFyneApp(t)

	t.Run("NewDisabledEntry", func(t *testing.T) {
		entry := NewDisabledEntry()
		if entry == nil {
			t.Fatal("Expected non-nil entry")
		}

		// Should be disabled
		if !entry.Disabled() {
			t.Error("Expected entry to be disabled")
		}
	})

	t.Run("SetText", func(t *testing.T) {
		entry := NewDisabledEntry()
		entry.SetText("Test content")

		if entry.Text != "Test content" {
			t.Errorf("Expected text 'Test content', got '%s'", entry.Text)
		}
	})
}

// TestTooltipButton tests the tooltip button widget.
func TestTooltipButton(t *testing.T) {
	newTestFyneApp(t)

	t.Run("NewTooltipButton", func(t *testing.T) {
		tapped := false
		btn := NewTooltipButton("Click", "This is a tooltip", func() {
			tapped = true
		})

		if btn == nil {
			t.Fatal("Expected non-nil button")
		}
		if btn.Text != "Click" {
			t.Errorf("Expected text 'Click', got '%s'", btn.Text)
		}
		if btn.tooltip != "This is a tooltip" {
			t.Errorf("Expected tooltip 'This is a tooltip', got '%s'", btn.tooltip)
		}

		// Simulate tap
		test.Tap(btn)
		if !tapped {
			t.Error("Expected OnTapped to be called")
		}
	})

	t.Run("SetTooltip", func(t *testing.T) {
		btn := NewTooltipButton("Click", "Initial", nil)
		btn.SetTooltip("Updated tooltip")

		if btn.tooltip != "Updated tooltip" {
			t.Errorf("Expected tooltip 'Updated tooltip', got '%s'", btn.tooltip)
		}
	})
}

// TestFixedWidthLayout tests the fixed width layout.
func TestFixedWidthLayout(t *testing.T) {
	newTestFyneApp(t)

	t.Run("MinSize_Empty", func(t *testing.T) {
		layout := &fixedWidthLayout{width: 100}
		minSize := layout.MinSize(nil)

		if minSize.Width != 100 {
			t.Errorf("Expected width 100, got %f", minSize.Width)
		}
		if minSize.Height != 0 {
			t.Errorf("Expected height 0, got %f", minSize.Height)
		}
	})

	t.Run("MinSize_WithObject", func(t *testing.T) {
		layout := &fixedWidthLayout{width: 100}

		// Create a simple label widget
		label := NewColoredLabel("Test", color.White)
		objects := []fyne.CanvasObject{label}
		minSize := layout.MinSize(objects)

		if minSize.Width != 100 {
			t.Errorf("Expected width 100, got %f", minSize.Width)
		}
	})

	t.Run("Layout", func(t *testing.T) {
		layout := &fixedWidthLayout{width: 100}

		// Create a simple label widget
		label := NewColoredLabel("Test", color.White)
		objects := []fyne.CanvasObject{label}

		// Apply layout
		layout.Layout(objects, fyne.NewSize(200, 50))

		// Check that object was resized to fixed width
		if label.Size().Width != 100 {
			t.Errorf("Expected object width 100, got %f", label.Size().Width)
		}
	})
}

// TestCompactTheme tests the compact theme.
func TestCompactTheme(t *testing.T) {
	t.Run("NewCompactTheme", func(t *testing.T) {
		theme := NewCompactTheme()
		if theme == nil {
			t.Fatal("Expected non-nil theme")
		}
	})

	t.Run("Size", func(t *testing.T) {
		theme := NewCompactTheme().(*CompactTheme)

		// Test custom sizes for improved readability
		textSize := theme.Size("text")
		if textSize != 14 {
			t.Errorf("Expected text size 14, got %f", textSize)
		}

		paddingSize := theme.Size("padding")
		if paddingSize != 6 {
			t.Errorf("Expected padding 6, got %f", paddingSize)
		}
	})

	t.Run("Color", func(t *testing.T) {
		theme := NewCompactTheme().(*CompactTheme)

		// Enhanced-contrast foreground: near-white in dark mode, near-black in light mode.
		dark := theme.Color(fynetheme.ColorNameForeground, fynetheme.VariantDark)
		wantDark := color.RGBA{R: 0xF5, G: 0xF5, B: 0xF5, A: 0xFF}
		if dark != wantDark {
			t.Errorf("dark foreground: expected %v, got %v", wantDark, dark)
		}

		light := theme.Color(fynetheme.ColorNameForeground, fynetheme.VariantLight)
		wantLight := color.RGBA{R: 0x10, G: 0x10, B: 0x10, A: 0xFF}
		if light != wantLight {
			t.Errorf("light foreground: expected %v, got %v", wantLight, light)
		}
	})

	t.Run("Font", func(t *testing.T) {
		theme := NewCompactTheme().(*CompactTheme)

		font := theme.Font(fyne.TextStyle{})
		if font == nil {
			t.Error("Expected non-nil font")
		}
	})

	t.Run("Icon", func(t *testing.T) {
		theme := NewCompactTheme().(*CompactTheme)

		icon := theme.Icon("cancel")
		if icon == nil {
			t.Error("Expected non-nil icon")
		}
	})
}
