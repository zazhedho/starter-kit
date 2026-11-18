// Command api runs the service until SIGINT or SIGTERM; a second signal during shutdown exits immediately.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/zazhedho/logus"

	"starter-kit/internal/app"
)

func main() {
	os.Exit(execute(os.Args[1:], app.Run))
}

// execute runs the service and returns the process exit code. run is a
// parameter so the signal handling and exit behavior can be tested.
func execute(args []string, run func(context.Context, []string) error) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// After the first signal the context is canceled and the shutdown runs.
	// Restoring the default handling then lets a second SIGINT or SIGTERM end
	// the process at once, instead of being swallowed while shutdown waits.
	go func() {
		<-ctx.Done()
		stop()
	}()

	if err := run(ctx, args); err != nil {
		// The error can come from startup, from serving, or from shutdown;
		// its text says which.
		logus.WriteLog(logus.LogLevelError, "service exited with error: ", err)
		return 1
	}
	return 0
}
