package ui

import "testing"

func TestKeyfileDisplayLabelUsesSemanticState(t *testing.T) {
	newTestFyneApp(t)

	tests := []struct {
		name       string
		required   bool
		count      int
		applicable bool
		want       string
	}{
		{name: "not applicable", applicable: false, want: "Not applicable"},
		{name: "none selected", applicable: true, want: "None selected"},
		{name: "required", required: true, applicable: true, want: "Keyfiles required"},
		{name: "one selected", count: 1, applicable: true, want: "Using 1 keyfile"},
		{name: "many selected", count: 3, applicable: true, want: "Using 3 keyfiles"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyfileDisplayLabel(tt.required, tt.count, tt.applicable); got != tt.want {
				t.Fatalf("keyfileDisplayLabel(%v, %d, %v) = %q; want %q", tt.required, tt.count, tt.applicable, got, tt.want)
			}
		})
	}
}
