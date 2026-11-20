package media

import (
	"os"
	"testing"

	"starter-kit/internal/testutil/logcapture"
)

var logs *logcapture.Capture

func TestMain(m *testing.M) {
	logs = logcapture.Start()
	code := m.Run()
	if code != 0 {
		_, _ = os.Stderr.WriteString(logs.All())
	}
	logs.Stop()
	os.Exit(code)
}
