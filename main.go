package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/tomventa/wirebalancer/internal/config"
	"github.com/tomventa/wirebalancer/internal/proxy"
	"github.com/tomventa/wirebalancer/internal/stats"
	"github.com/tomventa/wirebalancer/internal/webserver"
	"github.com/tomventa/wirebalancer/internal/wireguard"
)

func main() {
	configPath := flag.String("config", "config.yml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize stats tracker
	statsTracker := stats.NewTracker(len(cfg.WireGuard.Connections))

	// Initialize WireGuard manager
	wgManager := wireguard.NewManager(cfg.WireGuard, statsTracker)
	if err := wgManager.Initialize(); err != nil {
		log.Fatalf("Failed to initialize WireGuard: %v", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start health checks
	go wgManager.StartHealthChecks(ctx)

	// Initialize proxy manager
	proxyManager := proxy.NewManager(cfg.Proxy, wgManager, statsTracker)

	// Start SOCKS5 proxies
	var wg sync.WaitGroup
	for i := 0; i < len(cfg.WireGuard.Connections)+1; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			port := cfg.Proxy.BasePort + index
			if err := proxyManager.StartProxy(ctx, index, port); err != nil {
				log.Printf("Failed to start proxy on port %d: %v", port, err)
			}
		}(i)
	}

	// Start web server for stats
	webServer := webserver.New(cfg.WebServer.Port, statsTracker, wgManager)
	go func() {
		if err := webServer.Start(); err != nil {
			log.Printf("Web server error: %v", err)
		}
	}()

	log.Printf("WireBalancer started successfully")
	log.Printf("Random proxy: localhost:%d", cfg.Proxy.BasePort)
	for i := 0; i < len(cfg.WireGuard.Connections); i++ {
		log.Printf("Connection %d proxy: localhost:%d", i, cfg.Proxy.BasePort+i+1)
	}
	log.Printf("Stats dashboard: http://localhost:%d", cfg.WebServer.Port)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down gracefully...")
	cancel()

	// Wait for all goroutines with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All proxies stopped")
	case <-time.After(10 * time.Second):
		log.Println("Shutdown timeout, forcing exit")
	}

	wgManager.Cleanup()
	log.Println("Shutdown complete")
}
