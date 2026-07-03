package main

import (
	"context"
	"log"
	"log/slog"

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

	go controllers.StartRenewalScheduler(context.Background())

	r := routes.SetupRouter()

	addr := config.Cfg.Server.Addr
	port := config.Cfg.Server.Port
	if addr != "" {
		addr = addr + ":"
	} else {
		addr = ":"
	}

	slog.Info("starting server", "addr", addr+port)
	if err := r.Run(addr + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
