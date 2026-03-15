package ui

import (
	"reflect"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
)

func TestBuildEncryptOptionsDoNotUseTooltipCheckboxes(t *testing.T) {
	test.NewApp()
	defer test.NewApp()

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()

	a.buildEncryptOptions()

	if got := countTooltipCheckboxes(a.advancedContainer); got != 0 {
		t.Fatalf("buildEncryptOptions created %d TooltipCheckbox widgets, want 0", got)
	}
}

func TestBuildDecryptOptionsDoNotUseTooltipCheckboxes(t *testing.T) {
	test.NewApp()
	defer test.NewApp()

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()
	a.State.InputFile = "volume.zip.pcv"

	a.buildDecryptOptions()

	if got := countTooltipCheckboxes(a.advancedContainer); got != 0 {
		t.Fatalf("buildDecryptOptions created %d TooltipCheckbox widgets, want 0", got)
	}
}

func TestBuildMobileEncryptOptionsDoNotUseTooltipCheckboxes(t *testing.T) {
	test.NewApp()
	defer test.NewApp()

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()

	a.buildMobileEncryptOptions()

	if got := countTooltipCheckboxes(a.advancedContainer); got != 0 {
		t.Fatalf("buildMobileEncryptOptions created %d TooltipCheckbox widgets, want 0", got)
	}
}

func TestBuildMobileDecryptOptionsDoNotUseTooltipCheckboxes(t *testing.T) {
	test.NewApp()
	defer test.NewApp()

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()

	a.buildMobileDecryptOptions()

	if got := countTooltipCheckboxes(a.advancedContainer); got != 0 {
		t.Fatalf("buildMobileDecryptOptions created %d TooltipCheckbox widgets, want 0", got)
	}
}

func countTooltipCheckboxes(obj fyne.CanvasObject) int {
	count := 0
	countTooltipCheckboxesInto(obj, &count)
	return count
}

func countTooltipCheckboxesInto(obj fyne.CanvasObject, count *int) {
	switch typed := obj.(type) {
	case *fyne.Container:
		for _, child := range typed.Objects {
			countTooltipCheckboxesInto(child, count)
		}
	default:
		if reflect.TypeOf(obj).String() == "*ui.TooltipCheckbox" {
			*count = *count + 1
		}
	}
}
