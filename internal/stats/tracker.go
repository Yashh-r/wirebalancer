package stats

import (
	"sync"
	"sync/atomic"
	"time"
)

type ConnectionStats struct {
	RequestCount  atomic.Int64
	IsHealthy     atomic.Bool
	LatencySum    atomic.Int64 // in nanoseconds
	LatencyCount  atomic.Int64
	LastCheckTime atomic.Int64 // unix timestamp
}

type Tracker struct {
	totalRequests atomic.Int64
	connections   []ConnectionStats
	startTime     time.Time
	mu            sync.RWMutex
}

func NewTracker(numConnections int) *Tracker {
	t := &Tracker{
		connections: make([]ConnectionStats, numConnections),
		startTime:   time.Now(),
	}

	// Initialize all connections as unhealthy by default
	for i := range t.connections {
		t.connections[i].IsHealthy.Store(false)
	}

	return t
}

func (t *Tracker) IncrementRequests(connectionIndex int) {
	t.totalRequests.Add(1)
	if connectionIndex >= 0 && connectionIndex < len(t.connections) {
		t.connections[connectionIndex].RequestCount.Add(1)
	}
}

func (t *Tracker) SetConnectionHealth(connectionIndex int, healthy bool) {
	if connectionIndex >= 0 && connectionIndex < len(t.connections) {
		t.connections[connectionIndex].IsHealthy.Store(healthy)
		t.connections[connectionIndex].LastCheckTime.Store(time.Now().Unix())
	}
}

func (t *Tracker) RecordLatency(connectionIndex int, latency time.Duration) {
	if connectionIndex >= 0 && connectionIndex < len(t.connections) {
		t.connections[connectionIndex].LatencySum.Add(int64(latency))
		t.connections[connectionIndex].LatencyCount.Add(1)
	}
}

func (t *Tracker) GetTotalRequests() int64 {
	return t.totalRequests.Load()
}

func (t *Tracker) GetConnectionRequests(connectionIndex int) int64 {
	if connectionIndex >= 0 && connectionIndex < len(t.connections) {
		return t.connections[connectionIndex].RequestCount.Load()
	}
	return 0
}

func (t *Tracker) IsConnectionHealthy(connectionIndex int) bool {
	if connectionIndex >= 0 && connectionIndex < len(t.connections) {
		return t.connections[connectionIndex].IsHealthy.Load()
	}
	return false
}

func (t *Tracker) GetAverageLatency(connectionIndex int) time.Duration {
	if connectionIndex >= 0 && connectionIndex < len(t.connections) {
		sum := t.connections[connectionIndex].LatencySum.Load()
		count := t.connections[connectionIndex].LatencyCount.Load()
		if count == 0 {
			return 0
		}
		return time.Duration(sum / count)
	}
	return 0
}

func (t *Tracker) GetLastCheckTime(connectionIndex int) time.Time {
	if connectionIndex >= 0 && connectionIndex < len(t.connections) {
		timestamp := t.connections[connectionIndex].LastCheckTime.Load()
		if timestamp == 0 {
			return time.Time{}
		}
		return time.Unix(timestamp, 0)
	}
	return time.Time{}
}

func (t *Tracker) GetUptime() time.Duration {
	return time.Since(t.startTime)
}

func (t *Tracker) GetNumConnections() int {
	return len(t.connections)
}

type Stats struct {
	TotalRequests int64            `json:"total_requests"`
	Uptime        string           `json:"uptime"`
	UptimeSeconds int64            `json:"uptime_seconds"`
	Connections   []ConnectionStat `json:"connections"`
}

type ConnectionStat struct {
	Index          int     `json:"index"`
	Name           string  `json:"name"`
	Healthy        bool    `json:"healthy"`
	RequestCount   int64   `json:"request_count"`
	AverageLatency string  `json:"average_latency"`
	LatencyMs      float64 `json:"latency_ms"`
	LastCheck      string  `json:"last_check"`
}

func (t *Tracker) GetStats() Stats {
	uptime := t.GetUptime().Round(time.Second)
	return Stats{
		TotalRequests: t.GetTotalRequests(),
		Uptime:        uptime.String(),
		UptimeSeconds: int64(uptime.Seconds()),
		Connections:   make([]ConnectionStat, 0, len(t.connections)),
	}
}
