package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"bty/src/go/internal/c2"
	"bty/src/go/internal/config"
	"bty/src/go/internal/db"
	"bty/src/go/internal/handlers"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	host := flag.String("host", "", "Override server host")
	port := flag.Int("port", 0, "Override C2 port")
	apiPort := flag.Int("api-port", 0, "Override API port")
	noTLS := flag.Bool("no-tls", false, "Disable TLS")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *host != "" {
		cfg.Server.Host = *host
	}
	if *port != 0 {
		cfg.Server.Port = uint16(*port)
	}
	if *apiPort != 0 {
		cfg.API.Port = uint16(*apiPort)
	}
	if *noTLS {
		cfg.TLS.Enabled = false
	}

	// Open database
	database, err := db.Open(cfg.Database.DSN)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	// Create operators from config (with pre-hashed passwords)
	for _, op := range cfg.Operators {
		if op.Password != "" {
			// Password is already bcrypt hashed in config
			if err := database.CreateOperatorWithHash(op.Username, op.Password, op.Role); err != nil {
				// Likely already exists, ignore
			}
		}
	}

	// Fallback: create default admin if no operators in config
	if len(cfg.Operators) == 0 {
		if err := database.CreateOperator("admin", "admin", "admin"); err != nil {
			// Likely already exists, ignore
		}
	}

	// Create and start server
	server := c2.New(cfg, database)

	// Wire up REST API handlers (separate package to avoid circular imports)
	router := handlers.NewRouter(server)
	server.SetAPIMux(router.Setup())

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	fmt.Printf(`
╔══════════════════════════════════════════════╗
║              BTY C2 Framework                ║
║         Command & Control Server             ║
╠══════════════════════════════════════════════╣
║  C2 Port:  %-33d ║
║  API Port: %-33d ║
║  TLS:      %-33v ║
║  DB:       %-33s ║
║  Sessions: %-33d ║
╚══════════════════════════════════════════════╝

C2 API:   http://localhost:%d/api/health
REST API: http://localhost:%d/api/sessions
`, cfg.Server.Port, cfg.API.Port, cfg.TLS.Enabled, cfg.Database.DSN, 0,
		cfg.API.Port, cfg.API.Port)

	log.Printf("[C2] Server ready")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[C2] Shutdown signal received")
	server.Stop()
}
