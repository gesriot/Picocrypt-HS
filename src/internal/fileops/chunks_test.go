package fileops

import "testing"

func TestIsSplitChunkPath(t *testing.T) {
	testCases := []struct {
		path string
		want bool
	}{
		{path: "archive.zip.pcv.0", want: true},
		{path: "archive.zip.pcv.12", want: true},
		{path: "backup.pcv.tmp1", want: false},
		{path: "notes.pcv.v2", want: false},
		{path: "file.pcv.txt", want: false},
	}

	for _, tc := range testCases {
		if got := IsSplitChunkPath(tc.path); got != tc.want {
			t.Fatalf("IsSplitChunkPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
