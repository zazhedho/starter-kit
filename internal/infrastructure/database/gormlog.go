package database

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/zazhedho/logus"
	gormlogger "gorm.io/gorm/logger"
)

const slowQueryThreshold = 200 * time.Millisecond

// Scan's parameter filter is a package-level hook that keeps bound values regardless of
// ParameterizedQueries; this keeps placeholders too.
func init() {
	gormlogger.RecorderParamsFilter = func(_ context.Context, sql string, _ ...any) (string, []any) {
		return sql, nil
	}
}

type logusWriter struct{}

func (logusWriter) Printf(format string, args ...any) {
	if len(args) > 0 {
		if loc, ok := args[0].(string); ok {
			args = append([]any{filepath.Base(loc)}, args[1:]...)
		}
	}
	msg := strings.Join(strings.Fields(fmt.Sprintf(format, args...)), " ")
	logus.Log(logus.LevelWarn, "gorm; "+msg)
}

func newQueryLogger() gormlogger.Interface {
	return gormlogger.New(logusWriter{}, gormlogger.Config{
		SlowThreshold:             slowQueryThreshold,
		LogLevel:                  gormlogger.Warn,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
	})
}
