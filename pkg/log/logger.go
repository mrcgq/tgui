package log

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New creates a zap.Logger from a level string.
func New(level string) (*zap.Logger, error) {
	return NewWithOutput(level, "stderr")
}

// NewWithOutput creates a zap.Logger with specified output.
func NewWithOutput(level, output string) (*zap.Logger, error) {
	var lvl zapcore.Level
	switch level {
	case "debug":
		lvl = zapcore.DebugLevel
	case "info", "":
		lvl = zapcore.InfoLevel
	case "warn":
		lvl = zapcore.WarnLevel
	case "error":
		lvl = zapcore.ErrorLevel
	default:
		return nil, fmt.Errorf("log: unknown level %q", level)
	}

	outputPaths := []string{"stderr"}
	errorPaths := []string{"stderr"}

	switch {
	case output == "stdout":
		outputPaths = []string{"stdout"}
		errorPaths = []string{"stderr"}
	case output == "stderr" || output == "":
	case strings.HasPrefix(output, "file:"):
		filePath := strings.TrimPrefix(output, "file:")
		outputPaths = []string{filePath}
		errorPaths = []string{filePath}
	default:
		outputPaths = []string{output}
	}

	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(lvl),
		Encoding:         "console",
		OutputPaths:      outputPaths,
		ErrorOutputPaths: errorPaths,
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			MessageKey:     "msg",
			CallerKey:      "caller",
			StacktraceKey:  "stacktrace",
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
		},
	}

	return cfg.Build(zap.AddStacktrace(zapcore.ErrorLevel))
}

// NewNop creates a no-op logger for testing.
func NewNop() *zap.Logger {
	return zap.NewNop()
}
