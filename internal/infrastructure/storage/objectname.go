package storage

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// buildObjectName returns <folder>/<UTC timestamp>_<random UUID><extension>. The
// full 122-bit UUID keeps a public object's URL unguessable.
func buildObjectName(filename, folder string) string {
	ext := filepath.Ext(filename)
	uniqueFilename := fmt.Sprintf("%s_%s%s", time.Now().UTC().Format("20060102_150405"), uuid.NewString(), ext)
	if folder == "" {
		return uniqueFilename
	}

	return fmt.Sprintf("%s/%s", strings.Trim(folder, "/"), uniqueFilename)
}
