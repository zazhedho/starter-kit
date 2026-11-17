// Command api is the service entrypoint: it runs the application until it
// receives SIGINT or SIGTERM, and exits non-zero if startup or serving fails.
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, os.Args[1:]); err != nil {
		logus.WriteLog(logus.LogLevelError, "startup failed: ", err)
		stop()
		os.Exit(1)
	}
}
