package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// SetupSignalContext devuelve un context cancelado al recibir SIGTERM o SIGINT.
// GitHub Actions envía SIGTERM con ~30s de gracia antes de SIGKILL al cancelar
// el job o alcanzar el timeout. Una segunda señal fuerza la salida inmediata.
func SetupSignalContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		slog.Info("señal recibida, iniciando shutdown graceful", "signal", sig.String())
		cancel()
		<-sigCh
		slog.Warn("segunda señal recibida, forzando salida")
		os.Exit(130)
	}()
	return ctx
}
