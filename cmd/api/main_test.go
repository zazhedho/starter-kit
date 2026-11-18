package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// When helperEnv is set, TestMain runs execute with a stand-in for app.Run instead of the tests.
const helperEnv = "STARTER_KIT_TEST_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "fail":
		os.Exit(execute(nil, func(context.Context, []string) error { return errors.New("boom while serving") }))
	case "slow-shutdown":
		// Like a service whose graceful shutdown takes a long time.
		os.Exit(execute(nil, func(ctx context.Context, _ []string) error {
			fmt.Println("ready")
			<-ctx.Done()
			fmt.Println("shutting down")
			time.Sleep(30 * time.Second)
			return nil
		}))
	default:
		os.Exit(2)
	}
}

func startHelper(t *testing.T, mode string) (*exec.Cmd, *bufio.Scanner) {
	t.Helper()
	//nolint:gosec // G204: re-runs this very test binary
	cmd := exec.CommandContext(context.Background(), os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd, bufio.NewScanner(out)
}

func TestErrorFromRunExitsWithOneAndIsNotCalledAStartupFailure(t *testing.T) {
	cmd, out := startHelper(t, "fail")
	var output strings.Builder
	for out.Scan() {
		output.WriteString(out.Text() + "\n")
	}
	err := cmd.Wait()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("exit = %v, want exit code 1", err)
	}
	if !strings.Contains(output.String(), "service exited with error: boom while serving") {
		t.Errorf("log lacks the neutral message with the cause: %q", output.String())
	}
	if strings.Contains(output.String(), "startup failed") {
		t.Errorf("an error that is not a startup failure is reported as one: %q", output.String())
	}
}

// waitLine reads lines until one equals want.
func waitLine(t *testing.T, out *bufio.Scanner, want string) {
	t.Helper()
	for out.Scan() {
		if strings.TrimSpace(out.Text()) == want {
			return
		}
	}
	t.Fatalf("the service never printed %q", want)
}

// TestSecondSignalEndsTheProcess: the first SIGTERM starts a graceful
// shutdown (which here takes 30 s); a second one must end the process at once.
func TestSecondSignalEndsTheProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a process cannot be sent SIGTERM on Windows")
	}
	cmd, out := startHelper(t, "slow-shutdown")
	waitLine(t, out, "ready")
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitLine(t, out, "shutting down")

	done := make(chan error, 1)
	go func() {
		for out.Scan() { // drain until the pipe closes with the process
		}
		done <- cmd.Wait()
	}()

	// Signal again until the process goes: the handler is restored a moment
	// after the first signal is seen, so an early second signal can still be
	// absorbed. Without the fix none of them ever ends it.
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("the process exited normally; it should have been terminated by the second signal")
			}
			return
		case <-tick.C:
			_ = cmd.Process.Signal(syscall.SIGTERM)
		case <-deadline:
			t.Fatal("a second SIGTERM did not end the process within 5 s")
		}
	}
}
