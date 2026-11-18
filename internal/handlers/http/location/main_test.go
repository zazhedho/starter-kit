package location

import (
	"os"
	"testing"

	"starter-kit/internal/testutil/logcapture"
)

// logs captures what the handlers log during the tests (see logcapture).
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
