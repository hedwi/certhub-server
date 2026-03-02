package main

import (
	"log"

	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/routes"
)

func main() {
	// Initialize the database connection
	config.InitDB()

	// Setup and start Gin router
	r := routes.SetupRouter()

	addr := config.Cfg.Server.Addr
	port := config.Cfg.Server.Port
	if addr != "" {
		addr = addr + ":"
	} else {
		addr = ":"
	}

	log.Printf("Starting server on %s%s", addr, port)
	err := r.Run(addr + port)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
