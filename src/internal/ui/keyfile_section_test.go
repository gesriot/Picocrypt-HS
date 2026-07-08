package ui

import "testing"

func TestKeyfileDisplayLabelUsesSemanticState(t *testing.T) {
	tests := []struct {
		name       string
		required   bool
		count      int
		applicable bool
		want       string
	}{
		{name: "not applicable", applicable: false, want: tr("keyfiles.not_applicable", "Not applicable")},
		{name: "none selected", applicable: true, want: tr("keyfiles.none_selected", "None selected")},
		{name: "required", required: true, applicable: true, want: tr("keyfiles.required", "Keyfiles required")},
		{name: "one selected", count: 1, applicable: true, want: trn("keyfiles.count", "Using {{.Count}} keyfile", 1, map[string]any{"Count": 1})},
		{name: "many selected", count: 3, applicable: true, want: trn("keyfiles.count", "Using {{.Count}} keyfiles", 3, map[string]any{"Count": 3})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyfileDisplayLabel(tt.required, tt.count, tt.applicable); got != tt.want {
				t.Fatalf("keyfileDisplayLabel(%v, %d, %v) = %q; want %q", tt.required, tt.count, tt.applicable, got, tt.want)
			}
		})
	}
}
