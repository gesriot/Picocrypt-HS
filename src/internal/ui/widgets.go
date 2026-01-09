// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"image/color"
	"math"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// PasswordStrengthIndicator is a custom widget that displays password strength
// as a circular arc, colored from red (weak) to green (strong).
type PasswordStrengthIndicator struct {
	widget.BaseWidget
	strength  int  // 0-4 (zxcvbn score)
	visible   bool // whether to show the indicator
	decryMode bool // hide in decrypt mode
}

// NewPasswordStrengthIndicator creates a new password strength indicator.
func NewPasswordStrengthIndicator() *PasswordStrengthIndicator {
	p := &PasswordStrengthIndicator{}
	p.ExtendBaseWidget(p)
	return p
}

// SetStrength updates the strength value (0-4).
func (p *PasswordStrengthIndicator) SetStrength(strength int) {
	p.strength = strength
	p.Refresh()
}

// SetVisible sets whether the indicator should be visible.
func (p *PasswordStrengthIndicator) SetVisible(visible bool) {
	p.visible = visible
	p.Refresh()
}

// SetDecryptMode sets whether in decrypt mode (hides the indicator).
func (p *PasswordStrengthIndicator) SetDecryptMode(decrypt bool) {
	p.decryMode = decrypt
	p.Refresh()
}

// MinSize returns the minimum size of the indicator.
func (p *PasswordStrengthIndicator) MinSize() fyne.Size {
	return fyne.NewSize(24, 24)
}

// CreateRenderer creates the renderer for the widget.
func (p *PasswordStrengthIndicator) CreateRenderer() fyne.WidgetRenderer {
	r := &passwordStrengthRenderer{indicator: p, lines: make([]*canvas.Line, 20)}
	// Pre-create line objects
	for i := range r.lines {
		line := canvas.NewLine(color.Transparent)
		line.StrokeWidth = 2
		r.lines[i] = line
	}
	r.updateLines()
	return r
}

type passwordStrengthRenderer struct {
	indicator *PasswordStrengthIndicator
	lines     []*canvas.Line
}

func (r *passwordStrengthRenderer) Layout(size fyne.Size) {}

func (r *passwordStrengthRenderer) MinSize() fyne.Size {
	return r.indicator.MinSize()
}

func (r *passwordStrengthRenderer) updateLines() {
	centerX := float32(12)
	centerY := float32(12)
	radius := float32(9)

	if !r.indicator.visible || r.indicator.decryMode {
		// Hide all lines
		for _, line := range r.lines {
			line.StrokeColor = color.Transparent
			canvas.Refresh(line)
		}
		return
	}

	// Calculate color based on strength (0-4)
	col := color.RGBA{
		R: uint8(0xc8 - 31*r.indicator.strength),
		G: uint8(0x4c + 31*r.indicator.strength),
		B: 0x4b,
		A: 0xff,
	}

	startAngle := -math.Pi / 2
	endAngle := math.Pi * (0.4*float64(r.indicator.strength) - 0.1)
	steps := len(r.lines)

	for i, line := range r.lines {
		t1 := startAngle + (endAngle-startAngle)*float64(i)/float64(steps)
		t2 := startAngle + (endAngle-startAngle)*float64(i+1)/float64(steps)

		if t1 > endAngle || r.indicator.strength == 0 {
			line.StrokeColor = color.Transparent
		} else {
			x1 := centerX + radius*float32(math.Cos(t1))
			y1 := centerY + radius*float32(math.Sin(t1))
			x2 := centerX + radius*float32(math.Cos(t2))
			y2 := centerY + radius*float32(math.Sin(t2))

			line.Position1 = fyne.NewPos(x1, y1)
			line.Position2 = fyne.NewPos(x2, y2)
			line.StrokeColor = col
		}
		canvas.Refresh(line)
	}
}

func (r *passwordStrengthRenderer) Refresh() {
	r.updateLines()
}

func (r *passwordStrengthRenderer) Destroy() {}

func (r *passwordStrengthRenderer) Objects() []fyne.CanvasObject {
	objects := make([]fyne.CanvasObject, len(r.lines))
	for i, line := range r.lines {
		objects[i] = line
	}
	return objects
}

// ValidationIndicator is a custom widget that displays a circular validation indicator.
// Shows green circle when valid, red circle when invalid, or invisible when not applicable.
type ValidationIndicator struct {
	widget.BaseWidget
	valid   bool // true = green, false = red
	visible bool // whether to show the indicator
}

// NewValidationIndicator creates a new validation indicator.
func NewValidationIndicator() *ValidationIndicator {
	v := &ValidationIndicator{}
	v.ExtendBaseWidget(v)
	return v
}

// SetValid sets whether the validation passed.
func (v *ValidationIndicator) SetValid(valid bool) {
	v.valid = valid
	v.Refresh()
}

// SetVisible sets whether the indicator should be visible.
func (v *ValidationIndicator) SetVisible(visible bool) {
	v.visible = visible
	v.Refresh()
}

// MinSize returns the minimum size of the indicator.
func (v *ValidationIndicator) MinSize() fyne.Size {
	return fyne.NewSize(24, 24)
}

// CreateRenderer creates the renderer for the widget.
func (v *ValidationIndicator) CreateRenderer() fyne.WidgetRenderer {
	r := &validationRenderer{indicator: v, lines: make([]*canvas.Line, 24)}
	centerX := float32(12)
	centerY := float32(12)
	radius := float32(9)
	steps := len(r.lines)

	// Pre-create circle line segments
	for i := range r.lines {
		t1 := 2 * math.Pi * float64(i) / float64(steps)
		t2 := 2 * math.Pi * float64(i+1) / float64(steps)

		x1 := centerX + radius*float32(math.Cos(t1))
		y1 := centerY + radius*float32(math.Sin(t1))
		x2 := centerX + radius*float32(math.Cos(t2))
		y2 := centerY + radius*float32(math.Sin(t2))

		line := canvas.NewLine(color.Transparent)
		line.StrokeWidth = 2
		line.Position1 = fyne.NewPos(x1, y1)
		line.Position2 = fyne.NewPos(x2, y2)
		r.lines[i] = line
	}
	r.updateColor()
	return r
}

type validationRenderer struct {
	indicator *ValidationIndicator
	lines     []*canvas.Line
}

func (r *validationRenderer) Layout(size fyne.Size) {}

func (r *validationRenderer) MinSize() fyne.Size {
	return r.indicator.MinSize()
}

func (r *validationRenderer) updateColor() {
	var col color.Color
	if !r.indicator.visible {
		col = color.Transparent
	} else if r.indicator.valid {
		col = color.RGBA{0x4c, 0xc8, 0x4b, 0xff} // Green
	} else {
		col = color.RGBA{0xc8, 0x4c, 0x4b, 0xff} // Red
	}

	for _, line := range r.lines {
		line.StrokeColor = col
		canvas.Refresh(line)
	}
}

func (r *validationRenderer) Refresh() {
	r.updateColor()
}

func (r *validationRenderer) Destroy() {}

func (r *validationRenderer) Objects() []fyne.CanvasObject {
	objects := make([]fyne.CanvasObject, len(r.lines))
	for i, line := range r.lines {
		objects[i] = line
	}
	return objects
}

// DisabledEntry is an Entry widget that appears disabled but still shows content.
type DisabledEntry struct {
	widget.Entry
}

// NewDisabledEntry creates a new disabled entry.
func NewDisabledEntry() *DisabledEntry {
	e := &DisabledEntry{}
	e.ExtendBaseWidget(e)
	e.Disable()
	return e
}

// SetText sets the text of the disabled entry.
func (e *DisabledEntry) SetText(text string) {
	e.Entry.SetText(text)
}

// PasswordEntry is an Entry widget that can toggle between password and text mode.
type PasswordEntry struct {
	widget.Entry
	hidden bool
}

// NewPasswordEntry creates a new password entry.
func NewPasswordEntry() *PasswordEntry {
	e := &PasswordEntry{hidden: true}
	e.ExtendBaseWidget(e)
	e.Password = true
	return e
}

// SetHidden sets whether the password is hidden.
func (e *PasswordEntry) SetHidden(hidden bool) {
	e.hidden = hidden
	e.Password = hidden
	e.Refresh()
}

// IsHidden returns whether the password is currently hidden.
func (e *PasswordEntry) IsHidden() bool {
	return e.hidden
}

// TooltipButton is a button with a tooltip that shows on hover.
type TooltipButton struct {
	widget.Button
	tooltip string
	popup   *widget.PopUp
}

var _ desktop.Hoverable = (*TooltipButton)(nil)

// NewTooltipButton creates a new button with a tooltip.
func NewTooltipButton(label string, tooltip string, onTapped func()) *TooltipButton {
	b := &TooltipButton{tooltip: tooltip}
	b.Text = label
	b.OnTapped = onTapped
	b.ExtendBaseWidget(b)
	return b
}

// MouseIn is called when the mouse enters the button - shows tooltip.
func (b *TooltipButton) MouseIn(e *desktop.MouseEvent) {
	if b.tooltip == "" || b.Disabled() {
		return
	}
	c := fyne.CurrentApp().Driver().CanvasForObject(b)
	if c == nil {
		return
	}
	// Use canvas.Text for simple single-line tooltip
	text := canvas.NewText(b.tooltip, theme.ForegroundColor())
	text.TextSize = theme.CaptionTextSize()
	// Add padding around the text
	bg := canvas.NewRectangle(theme.OverlayBackgroundColor())
	content := container.NewStack(bg, container.NewPadded(text))
	b.popup = widget.NewPopUp(content, c)
	pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(b)
	b.popup.ShowAtPosition(fyne.NewPos(pos.X, pos.Y+b.Size().Height+2))
}

// MouseMoved is called when the mouse moves within the button.
func (b *TooltipButton) MouseMoved(e *desktop.MouseEvent) {}

// MouseOut is called when the mouse leaves the button - hides tooltip.
func (b *TooltipButton) MouseOut() {
	if b.popup != nil {
		b.popup.Hide()
		b.popup = nil
	}
}

// TooltipCheckbox is a checkbox with a tooltip that shows on hover.
type TooltipCheckbox struct {
	widget.Check
	tooltip string
	popup   *widget.PopUp
}

var _ desktop.Hoverable = (*TooltipCheckbox)(nil)

// NewTooltipCheckbox creates a new checkbox with a tooltip.
func NewTooltipCheckbox(label string, tooltip string, changed func(bool)) *TooltipCheckbox {
	c := &TooltipCheckbox{tooltip: tooltip}
	c.Text = label
	c.OnChanged = changed
	c.ExtendBaseWidget(c)
	return c
}

// MouseIn is called when the mouse enters the checkbox - shows tooltip.
func (c *TooltipCheckbox) MouseIn(e *desktop.MouseEvent) {
	if c.tooltip == "" || c.Disabled() {
		return
	}
	cv := fyne.CurrentApp().Driver().CanvasForObject(c)
	if cv == nil {
		return
	}
	// Use canvas.Text for simple single-line tooltip
	text := canvas.NewText(c.tooltip, theme.ForegroundColor())
	text.TextSize = theme.CaptionTextSize()
	// Add padding around the text
	bg := canvas.NewRectangle(theme.OverlayBackgroundColor())
	content := container.NewStack(bg, container.NewPadded(text))
	c.popup = widget.NewPopUp(content, cv)
	pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(c)
	c.popup.ShowAtPosition(fyne.NewPos(pos.X, pos.Y+c.Size().Height+2))
}

// MouseMoved is called when the mouse moves within the checkbox.
func (c *TooltipCheckbox) MouseMoved(e *desktop.MouseEvent) {}

// MouseOut is called when the mouse leaves the checkbox - hides tooltip.
func (c *TooltipCheckbox) MouseOut() {
	if c.popup != nil {
		c.popup.Hide()
		c.popup = nil
	}
}

// ColoredLabel is a label with custom text color.
type ColoredLabel struct {
	widget.BaseWidget
	text  string
	color color.Color
}

// NewColoredLabel creates a new label with custom color.
func NewColoredLabel(text string, col color.Color) *ColoredLabel {
	l := &ColoredLabel{text: text, color: col}
	l.ExtendBaseWidget(l)
	return l
}

// SetText updates the label text.
func (l *ColoredLabel) SetText(text string) {
	l.text = text
	l.Refresh()
}

// SetColor updates the label color.
func (l *ColoredLabel) SetColor(col color.Color) {
	l.color = col
	l.Refresh()
}

// MinSize returns the minimum size needed to display the label.
func (l *ColoredLabel) MinSize() fyne.Size {
	textSize := fyne.MeasureText(l.text, theme.TextSize(), fyne.TextStyle{})
	return textSize
}

// CreateRenderer creates the renderer for the colored label.
func (l *ColoredLabel) CreateRenderer() fyne.WidgetRenderer {
	text := canvas.NewText(l.text, l.color)
	text.TextSize = theme.TextSize()
	return &coloredLabelRenderer{label: l, text: text}
}

type coloredLabelRenderer struct {
	label *ColoredLabel
	text  *canvas.Text
}

func (r *coloredLabelRenderer) Layout(size fyne.Size) {
	r.text.Move(fyne.NewPos(0, 0))
}

func (r *coloredLabelRenderer) MinSize() fyne.Size {
	return r.label.MinSize()
}

func (r *coloredLabelRenderer) Refresh() {
	r.text.Text = r.label.text
	r.text.Color = r.label.color
	canvas.Refresh(r.text)
}

func (r *coloredLabelRenderer) Destroy() {}

func (r *coloredLabelRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.text}
}
