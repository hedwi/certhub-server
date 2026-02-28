package main

import (
	"log"
	"os"

	"github.com/hedwi/certhub/config"
	"github.com/hedwi/certhub/routes"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found. Falling back to environment variables.")
	}

	// Initialize the database connection
	config.InitDB()

	// Setup and start Gin router
	r := routes.SetupRouter()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	err = r.Run(":" + port)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
