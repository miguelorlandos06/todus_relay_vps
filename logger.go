package main

import (
	"log/slog"
	"os"
	"strings"
)

// initLogger configura slog con handler JSON hacia stdout.
// El nivel se controla con LOG_LEVEL (debug/info/warn/error).
// GitHub Actions captura stdout; los logs JSON son fáciles de filtrar.
func initLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}
