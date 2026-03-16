package fileops

import "testing"

func TestIsSplitChunkPath(t *testing.T) {
	testCases := []struct {
		path string
		want bool
	}{
		{path: "archive.zip.pcv.0", want: true},
		{path: "archive.zip.pcv.12", want: true},
		{path: "ARCHIVE.ZIP.PCV.0", want: true},
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

func TestSplitChunkBase(t *testing.T) {
	testCases := []struct {
		path string
		want string
		ok   bool
	}{
		{path: "/tmp/archive.zip.pcv.0", want: "/tmp/archive.zip.pcv", ok: true},
		{path: "/tmp/ARCHIVE.ZIP.PCV.0", want: "/tmp/ARCHIVE.ZIP.PCV", ok: true},
		{path: "/tmp/backup.pcv.tmp1", want: "", ok: false},
	}

	for _, tc := range testCases {
		got, ok := SplitChunkBase(tc.path)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("SplitChunkBase(%q) = (%q, %v), want (%q, %v)", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSplitChunkBaseUnicodeExpansionBeforeSuffix(t *testing.T) {
	path := "/tmp/ȺȺȺ.PCV.1"
	want := "/tmp/ȺȺȺ.PCV"

	got, ok := SplitChunkBase(path)
	if !ok || got != want {
		t.Fatalf("SplitChunkBase(%q) = (%q, %v), want (%q, true)", path, got, ok, want)
	}
}
