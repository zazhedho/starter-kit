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

type Mark int

func Start() *Capture {
	r, w, err := os.Pipe()
	if err != nil {
		panic("logcapture: " + err.Error())
	}
	c := &Capture{w: w, r: r, prevL: log.Writer(), readEnd: make(chan struct{})}
	c.cond = sync.NewCond(&c.mu)
	go c.read()

	logus.SetOutput(w)
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

func (c *Capture) Mark() Mark {
	c.flush()
	c.mu.Lock()
	defer c.mu.Unlock()
	return Mark(c.buf.Len())
}

func (c *Capture) Since(m Mark) string {
	c.flush()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.buf.String()[m:]
	return syncMarker.ReplaceAllString(out, "")
}

func (c *Capture) All() string { return c.Since(0) }

func (c *Capture) Stop() {
	logus.SetOutput(nil)
	log.SetOutput(c.prevL)
	_ = c.w.Close()
	<-c.readEnd
	_ = c.r.Close()
}
