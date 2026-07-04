package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/controllers"
	"github.com/hedwi/certhub-server/routes"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
)

func main() {
	utils.InitLogger()

	if err := config.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	if err := services.InitCrypto(); err != nil {
		log.Fatalf("Failed to init encryption: %v", err)
	}

	config.InitDB()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go controllers.StartRenewalScheduler(ctx)

	r := routes.SetupRouter()

	addr := config.Cfg.Server.Addr
	port := config.Cfg.Server.Port
	if addr != "" {
		addr = addr + ":"
	} else {
		addr = ":"
	}
	listenAddr := addr + port

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: r,
	}

	go func() {
		slog.Info("starting server", "addr", listenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutdown signal received, stopping...")

	httpShutdownTimeout := 30 * time.Second
	httpCtx, httpCancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer httpCancel()
	if err := srv.Shutdown(httpCtx); err != nil {
		slog.Warn("HTTP server shutdown", "error", err, "timeout", httpShutdownTimeout)
	}

	jobTimeout := services.ACMEWorkDrainBudget()
	controllers.CancelAllCertJobs()
	if !controllers.WaitCertJobs(jobTimeout) {
		slog.Warn("certificate jobs did not finish after cancel",
			"timeout", jobTimeout,
		)
	}
	controllers.RollbackAllGeneratingDomains()

	slog.Info("server stopped")
}
