package logcapture

import (
	"log"
	"os"
	"strings"
	"testing"

	"github.com/zazhedho/logus"
)

var capture *Capture

func TestMain(m *testing.M) {
	capture = Start()
	code := m.Run()
	capture.Stop()
	os.Exit(code)
}

func TestSinceReturnsOnlyWhatWasLoggedAfterTheMark(t *testing.T) {
	logus.Log(logus.LevelError, "before-mark")
	mark := capture.Mark()
	logus.Log(logus.LevelError, "after-mark-logus")
	log.Print("after-mark-stdlib")
	got := capture.Since(mark)

	for _, want := range []string{"after-mark-logus", "after-mark-stdlib"} {
		if !strings.Contains(got, want) {
			t.Errorf("capture lacks %q: %q", want, got)
		}
	}
	if strings.Contains(got, "before-mark") || strings.Contains(got, "\x00") {
		t.Errorf("capture has text from before the mark or a sync marker: %q", got)
	}
}

// Start redirects logus through SetOutput; it never swaps os.Stdout.
func TestStdoutIsLeftAlone(t *testing.T) {
	if os.Stdout == capture.w {
		t.Fatal("os.Stdout points at the capture pipe")
	}
}
