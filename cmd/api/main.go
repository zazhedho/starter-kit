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

func execute(args []string, run func(context.Context, []string) error) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// After the first signal, restoring default handling lets a second SIGINT or SIGTERM end the
	// process while shutdown is still waiting.
	go func() {
		<-ctx.Done()
		stop()
	}()

	if err := run(ctx, args); err != nil {
		logus.Log(logus.LevelError, "service exited with error:", err)
		return 1
	}
	return 0
}
