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

// init makes Scan keep placeholders too: its parameter filter is a package-level
// hook that keeps bound values regardless of ParameterizedQueries.
func init() {
	gormlogger.RecorderParamsFilter = func(_ context.Context, sql string, _ ...any) (string, []any) {
		return sql, nil
	}
}

// logusWriter routes gorm's logger through logus: one line per report, caller
// location cut to the file name so no local path is logged.
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

// newQueryLogger warns on failed and slow queries. Bound values are never printed;
// a missing row is not a problem.
func newQueryLogger() gormlogger.Interface {
	return gormlogger.New(logusWriter{}, gormlogger.Config{
		SlowThreshold:             slowQueryThreshold,
		LogLevel:                  gormlogger.Warn,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
	})
}
