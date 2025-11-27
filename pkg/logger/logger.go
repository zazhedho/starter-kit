package logger

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

const (
	LogLevelPanic = 0
	LogLevelError = 1
	LogLevelFail  = 2
	LogLevelInfo  = 3
	LogLevelData  = 4
	LogLevelDebug = 5
	LogLevelWarn  = 6
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

func WriteLog(level int, msg ...any) {
	if _, ok := logLevelMap[level]; !ok {
		return
	}

	if logLevel, _ := strconv.Atoi(os.Getenv("LOG_LEVEL")); logLevel < level {
		return
	}

	logPrefix := fmt.Sprintf("[%s][%s][%s]", os.Getenv("ServerIP"), os.Getenv("NODE"), logLevelMap[level])
	switch level {
	case LogLevelPanic, LogLevelError:
		log.Println(time.Now().Format(".000000"), logPrefix, msg)
	case LogLevelFail, LogLevelInfo, LogLevelData, LogLevelDebug:
		fmt.Println(time.Now().Format("2006/01/02 15:04:05 .000000"), logPrefix, msg)
	}
}
