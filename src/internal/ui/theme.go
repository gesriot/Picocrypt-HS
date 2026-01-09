// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// CompactTheme is a custom theme that matches the original Picocrypt (giu) look.
// It uses smaller fonts and reduced padding for a more compact UI.
type CompactTheme struct{}

var _ fyne.Theme = (*CompactTheme)(nil)

// NewCompactTheme creates a new compact theme matching original Picocrypt styling.
func NewCompactTheme() fyne.Theme {
	return &CompactTheme{}
}

// Color returns the color for the specified name and variant.
// Automatically follows system theme (dark/light).
func (c *CompactTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// Pass through the variant from system - automatic dark/light detection
	return theme.DefaultTheme().Color(name, variant)
}

// Font returns the font resource for the specified text style.
func (c *CompactTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

// Icon returns the icon resource for the specified name.
func (c *CompactTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// Size returns the size for the specified name - this is where we make things compact.
func (c *CompactTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 12 // Default is 14
	case theme.SizeNameCaptionText:
		return 10 // Default is 11
	case theme.SizeNameSubHeadingText:
		return 11 // Default is 13
	case theme.SizeNameHeadingText:
		return 18 // Default is 24
	case theme.SizeNamePadding:
		return 4 // Default is 6 - reduced padding
	case theme.SizeNameInnerPadding:
		return 4 // Default is 8 - reduced inner padding
	case theme.SizeNameInlineIcon:
		return 18 // Default is 20
	case theme.SizeNameScrollBar:
		return 12 // Default is 16
	case theme.SizeNameScrollBarSmall:
		return 3 // Default is 3
	case theme.SizeNameSeparatorThickness:
		return 1 // Default is 1
	case theme.SizeNameInputBorder:
		return 1 // Default is 1
	case theme.SizeNameInputRadius:
		return 4 // Default is 5
	case theme.SizeNameSelectionRadius:
		return 3 // Default is 3
	default:
		return theme.DefaultTheme().Size(name)
	}
}
