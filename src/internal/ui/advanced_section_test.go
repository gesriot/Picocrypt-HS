package ui

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// assertCheckboxWiring verifies a build...Options checkbox is present, correctly
// labeled, and that its OnChanged closure drives the mapped State field in both
// directions. OnChanged is invoked directly (not SetChecked, which no-ops when
// the value is unchanged) so the production callback runs unconditionally.
func assertCheckboxWiring(t *testing.T, c *widget.Check, wantLabel string, getField func() bool) {
	t.Helper()
	if c == nil {
		t.Fatalf("checkbox %q is nil", wantLabel)
	}
	if c.Text != wantLabel {
		t.Fatalf("checkbox label = %q, want %q", c.Text, wantLabel)
	}
	if c.OnChanged == nil {
		t.Fatalf("checkbox %q has nil OnChanged", wantLabel)
	}
	c.OnChanged(true)
	if !getField() {
		t.Fatalf("checkbox %q OnChanged(true) did not flip its State field to true", wantLabel)
	}
	c.OnChanged(false)
	if getField() {
		t.Fatalf("checkbox %q OnChanged(false) did not flip its State field to false", wantLabel)
	}
}

func TestBuildEncryptOptionsWireCheckboxesToState(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()

	fyne.DoAndWait(func() {
		a.buildEncryptOptions()

		assertCheckboxWiring(t, a.paranoidCheck, "Paranoid mode", func() bool { return a.State.Paranoid })
		assertCheckboxWiring(t, a.compressCheck, "Compress files", func() bool { return a.State.Compress })
		assertCheckboxWiring(t, a.reedSolomonCheck, "Reed-Solomon", func() bool { return a.State.ReedSolomon })
		assertCheckboxWiring(t, a.deleteCheck, "Delete files", func() bool { return a.State.Delete })
		assertCheckboxWiring(t, a.deniabilityCheck, "Deniability", func() bool { return a.State.Deniability })
		assertCheckboxWiring(t, a.recursivelyCheck, "Recursively", func() bool { return a.State.Recursively })
		assertCheckboxWiring(t, a.splitCheck, "Split:", func() bool { return a.State.Split })
	})
}

func TestBuildDecryptOptionsWireCheckboxesToState(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()
	a.State.InputFile = "volume.zip.pcv"
	a.State.AutoUnzip = true

	fyne.DoAndWait(func() {
		a.buildDecryptOptions()

		assertCheckboxWiring(t, a.forceDecryptCheck, "Force decrypt", func() bool { return a.State.Keep })
		assertCheckboxWiring(t, a.verifyFirstCheck, "Verify first", func() bool { return a.State.VerifyFirst })
		assertCheckboxWiring(t, a.deleteVolumeCheck, "Delete volume", func() bool { return a.State.Delete })
		assertCheckboxWiring(t, a.sameLevelCheck, "Same level", func() bool { return a.State.SameLevel })

		// autoUnzip's OnChanged(false) also clears SameLevel, so assert it directly.
		if a.autoUnzipCheck == nil || a.autoUnzipCheck.Text != "Auto unzip" {
			t.Fatalf("autoUnzipCheck missing or mislabeled: %+v", a.autoUnzipCheck)
		}
		a.autoUnzipCheck.OnChanged(true)
		if !a.State.AutoUnzip {
			t.Fatal("Auto unzip OnChanged(true) did not set State.AutoUnzip")
		}
		a.autoUnzipCheck.OnChanged(false)
		if a.State.AutoUnzip {
			t.Fatal("Auto unzip OnChanged(false) did not clear State.AutoUnzip")
		}
	})
}

func TestBuildDecryptOptionsDisableGuards(t *testing.T) {
	newTestFyneApp(t)

	testCases := []struct {
		name             string
		inputFile        string
		autoUnzip        bool
		deniability      bool
		wantAutoUnzipOff bool
		wantSameLevelOff bool
		wantForceOff     bool
	}{
		{"ZipEnablesUnzip", "volume.zip.pcv", true, false, false, false, false},
		{"NonZipDisablesUnzip", "volume.pcv", true, false, true, true, false},
		{"ZipNoAutoUnzipDisablesSameLevel", "volume.zip.pcv", false, false, false, true, false},
		{"DeniabilityDisablesForceDecrypt", "volume.zip.pcv", true, true, false, false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := createTestApp(t)
			a.advancedContainer = container.NewVBox()
			a.State.InputFile = tc.inputFile
			a.State.AutoUnzip = tc.autoUnzip
			a.State.Deniability = tc.deniability

			fyne.DoAndWait(func() {
				a.buildDecryptOptions()
			})

			if got := a.autoUnzipCheck.Disabled(); got != tc.wantAutoUnzipOff {
				t.Errorf("autoUnzipCheck.Disabled() = %v, want %v", got, tc.wantAutoUnzipOff)
			}
			if got := a.sameLevelCheck.Disabled(); got != tc.wantSameLevelOff {
				t.Errorf("sameLevelCheck.Disabled() = %v, want %v", got, tc.wantSameLevelOff)
			}
			if got := a.forceDecryptCheck.Disabled(); got != tc.wantForceOff {
				t.Errorf("forceDecryptCheck.Disabled() = %v, want %v", got, tc.wantForceOff)
			}
		})
	}
}

func TestBuildMobileEncryptOptionsWireCheckboxesToState(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()

	fyne.DoAndWait(func() {
		a.buildMobileEncryptOptions()

		assertCheckboxWiring(t, a.paranoidCheck, "Paranoid mode", func() bool { return a.State.Paranoid })
		assertCheckboxWiring(t, a.compressCheck, "Compress files", func() bool { return a.State.Compress })
		assertCheckboxWiring(t, a.reedSolomonCheck, "Reed-Solomon", func() bool { return a.State.ReedSolomon })
		assertCheckboxWiring(t, a.deleteCheck, "Delete files", func() bool { return a.State.Delete })
		assertCheckboxWiring(t, a.deniabilityCheck, "Deniability", func() bool { return a.State.Deniability })
		assertCheckboxWiring(t, a.recursivelyCheck, "Recursively", func() bool { return a.State.Recursively })
		assertCheckboxWiring(t, a.splitCheck, "Split:", func() bool { return a.State.Split })
	})
}

func TestBuildMobileDecryptOptionsWireCheckboxesToState(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.advancedContainer = container.NewVBox()

	fyne.DoAndWait(func() {
		a.buildMobileDecryptOptions()

		assertCheckboxWiring(t, a.forceDecryptCheck, "Force decrypt", func() bool { return a.State.Keep })
		assertCheckboxWiring(t, a.verifyFirstCheck, "Verify first", func() bool { return a.State.VerifyFirst })
		assertCheckboxWiring(t, a.deleteCheck, "Delete encrypted", func() bool { return a.State.Delete })
	})
}
