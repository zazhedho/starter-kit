package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/zazhedho/logus"
)

// ErrShutdownTimeout is returned by Serve when requests were still running
// when the shutdown time limit ran out and had to be cut off.
var ErrShutdownTimeout = errors.New("app: shutdown timed out with requests still in flight")

// Serve builds the routes if that has not happened yet, then handles requests
// until ctx is canceled, stops accepting connections, and waits up to
// HTTP_SHUTDOWN_TIMEOUT for running requests. It closes the App on every path
// and returns nil after a clean shutdown, ErrShutdownTimeout when requests
// were cut off, or the build/listen/serve error.
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
	logus.WriteLog(logus.LogLevelInfo, "Listening on "+ln.Addr().String())

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

	logus.WriteLog(logus.LogLevelInfo, "Shutdown started")
	// The caller's ctx is already canceled; the shutdown limit is its own.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.HTTP.ShutdownTimeout)
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

	err = a.closeAfter(err)
	if err == nil {
		logus.WriteLog(logus.LogLevelInfo, "Shutdown complete")
	}
	return err
}

// closeAfter closes the App and joins any close error to err.
func (a *App) closeAfter(err error) error {
	if closeErr := a.Close(); closeErr != nil {
		return errors.Join(err, closeErr)
	}
	return err
}
