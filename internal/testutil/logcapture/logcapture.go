// Package logcapture lets a test binary read what the service logs.
// logus builds its logger on the first write, around the then-current os.Stdout;
// Start swaps in a pipe for that moment. Call it from TestMain, before any test logs.
package logcapture

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/zazhedho/logus"
)

const flushTimeout = 5 * time.Second

var syncMarker = regexp.MustCompile("\x00sync-[0-9]+\x00")

// Capture collects log output written after Start.
type Capture struct {
	w     *os.File
	r     *os.File
	prevL io.Writer

	mu      sync.Mutex
	cond    *sync.Cond
	buf     bytes.Buffer
	syncs   int
	readEnd chan struct{}
}

// Mark is a position in the captured output.
type Mark int

// Start captures logus output and the standard log package. It panics if the
// pipe cannot be created (out of file descriptors).
func Start() *Capture {
	r, w, err := os.Pipe()
	if err != nil {
		panic("logcapture: " + err.Error())
	}
	c := &Capture{w: w, r: r, prevL: log.Writer(), readEnd: make(chan struct{})}
	c.cond = sync.NewCond(&c.mu)
	go c.read()

	realStdout := os.Stdout
	os.Stdout = w
	// Written at error level so that a low LOG_LEVEL cannot skip it: the
	// first line that passes the level check is what builds the logger.
	logus.WriteLog(logus.LogLevelError, "logcapture started")
	os.Stdout = realStdout
	log.SetOutput(w)
	return c
}

func (c *Capture) read() {
	defer close(c.readEnd)
	chunk := make([]byte, 32<<10)
	for {
		n, err := c.r.Read(chunk)
		if n > 0 {
			c.mu.Lock()
			c.buf.Write(chunk[:n])
			c.mu.Unlock()
			c.cond.Broadcast()
		}
		if err != nil {
			return
		}
	}
}

// flush waits until everything written so far has been read from the pipe, by
// writing a marker and waiting for it to arrive.
func (c *Capture) flush() {
	c.mu.Lock()
	c.syncs++
	marker := fmt.Sprintf("\x00sync-%d\x00", c.syncs)
	c.mu.Unlock()
	if _, err := c.w.WriteString(marker); err != nil {
		return
	}

	deadline := time.AfterFunc(flushTimeout, func() { c.cond.Broadcast() })
	defer deadline.Stop()
	start := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for !bytes.Contains(c.buf.Bytes(), []byte(marker)) && time.Since(start) < flushTimeout {
		c.cond.Wait()
	}
}

// Mark returns the current end of the output.
func (c *Capture) Mark() Mark {
	c.flush()
	c.mu.Lock()
	defer c.mu.Unlock()
	return Mark(c.buf.Len())
}

// Since returns what was logged after m.
func (c *Capture) Since(m Mark) string {
	c.flush()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.buf.String()[m:]
	return syncMarker.ReplaceAllString(out, "")
}

// All returns everything captured so far.
func (c *Capture) All() string { return c.Since(0) }

// Stop restores log output and ends the capture; logus cannot be rebuilt, so call
// it only just before exit.
func (c *Capture) Stop() {
	log.SetOutput(c.prevL)
	_ = c.w.Close()
	<-c.readEnd
	_ = c.r.Close()
}
