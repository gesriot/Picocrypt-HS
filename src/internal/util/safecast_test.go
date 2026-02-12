package util

import (
	"math"
	"testing"
)

func TestSafeUint64ToInt64(t *testing.T) {
	tests := []struct {
		name   string
		input  uint64
		want   int64
		wantOK bool
	}{
		{"zero", 0, 0, true},
		{"one", 1, 1, true},
		{"max safe", math.MaxInt64, math.MaxInt64, true},
		{"overflow by one", math.MaxInt64 + 1, 0, false},
		{"max uint64", math.MaxUint64, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := SafeUint64ToInt64(tt.input)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("SafeUint64ToInt64(%d) = (%d, %v), want (%d, %v)",
					tt.input, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestSafeIntToInt32(t *testing.T) {
	tests := []struct {
		name   string
		input  int
		want   int32
		wantOK bool
	}{
		{"zero", 0, 0, true},
		{"positive", 100, 100, true},
		{"negative", -100, -100, true},
		{"max int32", math.MaxInt32, math.MaxInt32, true},
		{"min int32", math.MinInt32, math.MinInt32, true},
		{"overflow positive", math.MaxInt32 + 1, 0, false},
		{"overflow negative", math.MinInt32 - 1, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := SafeIntToInt32(tt.input)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("SafeIntToInt32(%d) = (%d, %v), want (%d, %v)",
					tt.input, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
