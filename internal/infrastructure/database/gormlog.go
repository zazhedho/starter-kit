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

// slowQueryThreshold is the duration from which gorm logs a query as slow.
const slowQueryThreshold = 200 * time.Millisecond

// init makes Scan keep placeholders too: gorm's Scan records the SQL through a
// recorder whose parameter filter is a package-level hook that defaults to
// keeping the bound values, regardless of ParameterizedQueries.
func init() {
	gormlogger.RecorderParamsFilter = func(_ context.Context, sql string, _ ...any) (string, []any) {
		return sql, nil
	}
}

// logusWriter lets gorm's logger write through logus. A message is joined onto
// one line so each report is one log entry, and the caller location gorm puts
// first is cut to the file name, so no local path reaches the log.
type logusWriter struct{}

func (logusWriter) Printf(format string, args ...any) {
	if len(args) > 0 {
		if loc, ok := args[0].(string); ok {
			args = append([]any{filepath.Base(loc)}, args[1:]...)
		}
	}
	msg := strings.Join(strings.Fields(fmt.Sprintf(format, args...)), " ")
	logus.WriteLog(logus.LogLevelWarn, "gorm; "+msg)
}

// newQueryLogger reports failed and slow queries at warn level. Bound values
// are never printed (the SQL keeps its $1, $2 placeholders), and a missing row
// is a normal result, not a problem.
func newQueryLogger() gormlogger.Interface {
	return gormlogger.New(logusWriter{}, gormlogger.Config{
		SlowThreshold:             slowQueryThreshold,
		LogLevel:                  gormlogger.Warn,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
	})
}
