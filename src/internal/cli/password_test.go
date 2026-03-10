package cli

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadPasswordLine(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "newline", input: "pw\n", want: "pw"},
		{name: "crlf", input: "pw\r\n", want: "pw"},
		{name: "eof without newline", input: "pw", want: "pw"},
		{name: "empty eof", input: "", want: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPasswordLine(bufio.NewReader(strings.NewReader(tc.input)))
			if err != nil {
				t.Fatalf("readPasswordLine() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("readPasswordLine() = %q, want %q", got, tc.want)
			}
		})
	}
}
