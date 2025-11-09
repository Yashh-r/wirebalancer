package webserver

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/tomventa/wirebalancer/internal/stats"
	"github.com/tomventa/wirebalancer/internal/wireguard"
)

//go:embed templates/*
var templates embed.FS

type Server struct {
	port      int
	stats     *stats.Tracker
	wgManager *wireguard.Manager
}

func New(port int, statsTracker *stats.Tracker, wgManager *wireguard.Manager) *Server {
	return &Server{
		port:      port,
		stats:     statsTracker,
		wgManager: wgManager,
	}
}

func (s *Server) Start() error {
	http.HandleFunc("/", s.handleDashboard)
	http.HandleFunc("/api/stats", s.handleStatsAPI)
	http.HandleFunc("/health", s.handleHealth)

	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	log.Printf("Starting web server on %s", addr)
	return http.ListenAndServe(addr, nil)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(templates, "templates/dashboard.html"))

	data := s.collectStats()
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (s *Server) handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data := s.collectStats()

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("JSON encoding error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) collectStats() stats.Stats {
	data := s.stats.GetStats()
	connections := s.wgManager.GetConnections()

	data.Connections = make([]stats.ConnectionStat, len(connections))
	for i, conn := range connections {
		avgLatency := s.stats.GetAverageLatency(i)
		lastCheck := s.stats.GetLastCheckTime(i)
		lastCheckStr := "Never"
		if !lastCheck.IsZero() {
			lastCheckStr = lastCheck.Format("15:04:05")
		}

		data.Connections[i] = stats.ConnectionStat{
			Index:          i,
			Name:           conn.Name,
			Healthy:        conn.IsHealthy(),
			RequestCount:   s.stats.GetConnectionRequests(i),
			AverageLatency: avgLatency.String(),
			LatencyMs:      float64(avgLatency.Milliseconds()),
			LastCheck:      lastCheckStr,
		}
	}

	return data
}
