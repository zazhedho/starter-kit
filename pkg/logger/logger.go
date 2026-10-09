package logger

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"starter-kit/utils"

	"log/slog"
)

const (
	LogLevelPanic = 0
	LogLevelError = 1
	LogLevelFail  = 2
	LogLevelInfo  = 3
	LogLevelData  = 4
	LogLevelWarn  = 5
	LogLevelDebug = 6
)

var logLevelMap = map[int]string{
	LogLevelPanic: "PANIC",
	LogLevelError: "ERROR",
	LogLevelFail:  "FAIL ",
	LogLevelInfo:  "INFO ",
	LogLevelData:  "DATA ",
	LogLevelDebug: "DEBUG",
	LogLevelWarn:  "WARN ",
}

var (
	loggerOnce sync.Once
	appLogger  *slog.Logger
)

type logIDContextKey struct{}
type userIDContextKey struct{}

func WriteLog(level int, msg ...any) {
	writeLog(context.Background(), 5, level, msg...)
}

func WriteLogWithContext(ctx context.Context, level int, msg ...any) {
	writeLog(ctx, 6, level, msg...)
}

func WithLogMetadata(ctx context.Context, logID, userID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if logID != "" {
		ctx = context.WithValue(ctx, logIDContextKey{}, logID)
	}
	if userID != "" {
		ctx = context.WithValue(ctx, userIDContextKey{}, userID)
	}
	return ctx
}

func writeLog(ctx context.Context, defaultLogLevel, level int, msg ...any) {
	if _, ok := logLevelMap[level]; !ok {
		return
	}

	if logLevel, _ := strconv.Atoi(utils.GetEnv("LOG_LEVEL", strconv.Itoa(defaultLogLevel))); logLevel < level {
		return
	}

	logger := getLogger()
	attrs := []slog.Attr{
		slog.String("server_ip", utils.GetEnv("ServerIP", "")),
	}
	attrs = append(attrs, callerAttrs(3)...)
	if node := utils.GetEnv("NODE", ""); node != "" {
		attrs = append(attrs, slog.String("node", node))
	}

	if ctx != nil {
		logID := utils.InterfaceString(ctx.Value(logIDContextKey{}))
		if logID == "" {
			logID = utils.GenerateLogId(ctx).String()
		}
		attrs = append(attrs, slog.String("log_id", logID))

		userID := utils.InterfaceString(ctx.Value(userIDContextKey{}))
		if userID == "" {
			if getter, ok := ctx.(interface{ Get(string) (any, bool) }); ok {
				if value, exists := getter.Get("userId"); exists {
					userID = utils.InterfaceString(value)
				}
			}
		}
		if userID != "" {
			attrs = append(attrs, slog.String("user_id", userID))
		}
	}

	logCtx := ctx
	if logCtx == nil {
		logCtx = context.Background()
	}
	fields := make([]any, 0, len(attrs))
	for _, attr := range attrs {
		fields = append(fields, attr)
	}

	logger.Log(logCtx, mapLevelToSlog(level), fmt.Sprint(msg...), fields...)
}

func getLogger() *slog.Logger {
	loggerOnce.Do(func() {
		format := utils.NormalizeKey(utils.GetEnv("LOG_FORMAT", "json"))
		options := &slog.HandlerOptions{Level: slog.LevelDebug}

		var handler slog.Handler
		switch format {
		case "text":
			handler = slog.NewTextHandler(os.Stdout, options)
		case "string":
			handler = newStringHandler(os.Stdout, options.Level)
		default:
			handler = slog.NewJSONHandler(os.Stdout, options)
		}

		appLogger = slog.New(handler)
	})

	return appLogger
}

func mapLevelToSlog(level int) slog.Level {
	switch level {
	case LogLevelPanic, LogLevelError:
		return slog.LevelError
	case LogLevelWarn:
		return slog.LevelWarn
	case LogLevelDebug:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

func callerAttrs(skip int) []slog.Attr {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return nil
	}

	sourceFile := normalizeSourceFile(file)
	sourceFunction := ""
	if fn := runtime.FuncForPC(pc); fn != nil {
		sourceFunction = fn.Name()
	}

	return []slog.Attr{
		slog.String("source_file", sourceFile),
		slog.Int("source_line", line),
		slog.String("source_function", sourceFunction),
	}
}

func normalizeSourceFile(file string) string {
	wd, err := os.Getwd()
	if err == nil {
		if rel, relErr := filepath.Rel(wd, file); relErr == nil && rel != "" && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}

	return filepath.ToSlash(file)
}

type stringHandler struct {
	mu     sync.Mutex
	writer io.Writer
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
}

func newStringHandler(writer io.Writer, level slog.Leveler) slog.Handler {
	if level == nil {
		level = slog.LevelInfo
	}
	return &stringHandler{
		writer: writer,
		level:  level,
	}
}

func (h *stringHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *stringHandler) Handle(_ context.Context, record slog.Record) error {
	fields := map[string]string{}
	for _, attr := range h.attrs {
		h.addStringAttr(fields, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		h.addStringAttr(fields, attr)
		return true
	})

	level := strings.ToUpper(record.Level.String())
	prefix := fmt.Sprintf("[%s][%s][%s]", fields["server_ip"], fields["node"], level)
	if logID := fields["log_id"]; logID != "" {
		prefix += fmt.Sprintf("[%s]", logID)
	}
	if userID := fields["user_id"]; userID != "" {
		prefix += fmt.Sprintf("[%s]", userID)
	}
	if sourceFile := fields["source_file"]; sourceFile != "" {
		prefix += fmt.Sprintf("[%s:%s]", sourceFile, fields["source_line"])
	}

	ts := record.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	line := fmt.Sprintf("%s %s %s\n", ts.Format("2006/01/02 15:04:05 .000000"), prefix, record.Message)

	h.mu.Lock()
	_, err := io.WriteString(h.writer, line)
	h.mu.Unlock()
	return err
}

func (h *stringHandler) addStringAttr(fields map[string]string, attr slog.Attr) {
	if attr.Key == "" {
		return
	}
	key := attr.Key
	value := attr.Value
	if value.Kind() == slog.KindAny {
		if logValue, ok := value.Any().(slog.LogValuer); ok {
			value = logValue.LogValue()
		}
	}
	if len(h.groups) > 0 {
		key = strings.Join(h.groups, ".") + "." + key
	}
	if value.Kind() == slog.KindString {
		fields[key] = value.String()
		return
	}
	fields[key] = fmt.Sprint(value.Any())
}

func (h *stringHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &stringHandler{
		writer: h.writer,
		level:  h.level,
		attrs:  append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups: append([]string{}, h.groups...),
	}
}

func (h *stringHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &stringHandler{
		writer: h.writer,
		level:  h.level,
		attrs:  append([]slog.Attr{}, h.attrs...),
		groups: append(append([]string{}, h.groups...), name),
	}
}
