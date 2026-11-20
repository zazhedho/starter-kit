package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/zazhedho/logus"
)

// ErrShutdownTimeout is returned by Serve when requests were still running
// when the shutdown time limit ran out and had to be cut off.
var ErrShutdownTimeout = errors.New("app: shutdown timed out with requests still in flight")

// Serve handles requests until ctx ends, then waits up to HTTP_SHUTDOWN_TIMEOUT
// (one deadline) for requests and background work, and closes the App on every path.
// It returns nil on clean shutdown, ErrShutdownTimeout if requests were cut off.
func (a *App) Serve(ctx context.Context) error {
	if err := a.buildRoutes(); err != nil {
		return a.closeAfter(err)
	}
	ln := a.listener
	if ln == nil {
		var lc net.ListenConfig
		var err error
		if ln, err = lc.Listen(ctx, "tcp", a.server.Addr); err != nil {
			return a.closeAfter(fmt.Errorf("listen: %w", err))
		}
	}
	logus.Log(logus.LevelInfo, "Listening on", ln.Addr())

	serveErr := make(chan error, 1)
	go func() { serveErr <- a.server.Serve(ln) }()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return a.closeAfter(nil)
		}
		return a.closeAfter(fmt.Errorf("serve: %w", err))
	case <-ctx.Done():
	}

	logus.Log(logus.LevelInfo, "Shutdown started")
	// One deadline for the whole shutdown: the HTTP drain, the lifecycle hooks
	// and the final writes of the jobs they stop all end by it. The caller's
	// ctx is already canceled; the limit is its own.
	deadline := time.Now().Add(a.cfg.HTTP.ShutdownTimeout)
	shutdownCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()

	err := a.server.Shutdown(shutdownCtx)
	if err != nil {
		_ = a.server.Close() // cut off whatever is still running
		if errors.Is(err, context.DeadlineExceeded) {
			err = ErrShutdownTimeout
		} else {
			err = fmt.Errorf("shutdown: %w", err)
		}
	}
	<-serveErr // Serve has returned http.ErrServerClosed by now

	if closeErr := a.closeBy(deadline); closeErr != nil {
		err = errors.Join(err, closeErr)
	}
	if err == nil {
		logus.Log(logus.LevelInfo, "Shutdown complete")
	}
	return err
}

func (a *App) closeAfter(err error) error {
	if closeErr := a.Close(); closeErr != nil {
		return errors.Join(err, closeErr)
	}
	return err
}
