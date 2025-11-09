package wireguard

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tomventa/wirebalancer/internal/config"
	"github.com/tomventa/wirebalancer/internal/stats"
)

type Connection struct {
	Index         int
	Name          string
	InterfaceName string
	ConfigPath    string
	healthy       atomic.Bool
	failureCount  atomic.Int32
	lastCheck     atomic.Int64 // unix timestamp
}

type Manager struct {
	connections      []*Connection
	cfg              config.WireGuardConfig
	stats            *stats.Tracker
	healthCheckURL   string
	checkInterval    time.Duration
	failureThreshold int
}

func NewManager(cfg config.WireGuardConfig, statsTracker *stats.Tracker) *Manager {
	m := &Manager{
		connections:      make([]*Connection, len(cfg.Connections)),
		cfg:              cfg,
		stats:            statsTracker,
		healthCheckURL:   cfg.HealthCheckURL,
		checkInterval:    time.Duration(cfg.HealthCheckInterval) * time.Second,
		failureThreshold: cfg.FailureThreshold,
	}

	for i, connCfg := range cfg.Connections {
		conn := &Connection{
			Index:         i,
			Name:          connCfg.Name,
			InterfaceName: connCfg.InterfaceName,
			ConfigPath:    connCfg.ConfigPath,
		}
		conn.healthy.Store(false)
		m.connections[i] = conn
	}

	return m
}

func (m *Manager) Initialize() error {
	log.Println("Initializing WireGuard connections...")

	var wg sync.WaitGroup
	errChan := make(chan error, len(m.connections))

	for _, conn := range m.connections {
		wg.Add(1)
		go func(c *Connection) {
			defer wg.Done()
			if err := m.bringUpConnection(c); err != nil {
				errChan <- fmt.Errorf("connection %s: %w", c.Name, err)
			}
		}(conn)
	}

	wg.Wait()
	close(errChan)

	// Check if we had any errors
	for err := range errChan {
		log.Printf("Warning during initialization: %v", err)
	}

	// Perform initial health check
	for _, conn := range m.connections {
		if err := m.checkHealth(conn); err != nil {
			log.Printf("Initial health check failed for %s: %v", conn.Name, err)
		}
	}

	return nil
}

func (m *Manager) bringUpConnection(conn *Connection) error {
	log.Printf("Bringing up WireGuard connection: %s (%s)", conn.Name, conn.InterfaceName)

	// Check if config file exists and has correct permissions
	info, err := os.Stat(conn.ConfigPath)
	if err != nil {
		return fmt.Errorf("config file error: %w", err)
	}

	// Check permissions - warn if too permissive but continue
	if info.Mode().Perm() != 0600 {
		log.Printf("Warning: %s has permissions %o, should be 0600. Attempting to fix...",
			conn.ConfigPath, info.Mode().Perm())
		if err := os.Chmod(conn.ConfigPath, 0600); err != nil {
			log.Printf("Warning: Could not fix permissions: %v", err)
		}
	}

	// First, try to bring down if it exists
	downCmd := exec.Command("ip", "link", "del", conn.InterfaceName)
	downCmd.Run() // Ignore errors, interface might not exist

	// Create the WireGuard interface
	cmd := exec.Command("ip", "link", "add", "dev", conn.InterfaceName, "type", "wireguard")
	if output, err := cmd.CombinedOutput(); err != nil {
		// Interface might already exist, try to continue
		log.Printf("Note: %s", string(output))
	}

	// Parse the config to strip out non-WireGuard settings and get addresses
	wgConfig, addresses, err := m.parseWireGuardConfig(conn.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Create a temporary file with only WireGuard-specific settings
	tmpFile, err := os.CreateTemp("", "wg-*.conf")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(wgConfig); err != nil {
		return fmt.Errorf("failed to write temp config: %w", err)
	}
	tmpFile.Close()

	// Apply WireGuard configuration using wg setconf with stripped config
	cmd = exec.Command("wg", "setconf", conn.InterfaceName, tmpFile.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set wireguard config: %w (output: %s)", err, output)
	}

	// Set all IP addresses (both IPv4 and IPv6)
	for _, address := range addresses {
		cmd = exec.Command("ip", "address", "add", address, "dev", conn.InterfaceName)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Address might already exist, just log warning
			log.Printf("Warning adding address %s: %s", address, string(output))
		}
	}

	// Bring the interface up
	cmd = exec.Command("ip", "link", "set", "up", "dev", conn.InterfaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring up interface: %w (output: %s)", err, output)
	}

	// Set MTU if needed
	cmd = exec.Command("ip", "link", "set", "dev", conn.InterfaceName, "mtu", "1420")
	cmd.Run() // Ignore errors

	// CRITICAL: We do NOT add default routes here
	// This prevents routing conflicts between multiple WireGuard interfaces
	// Traffic routing is handled by SO_BINDTODEVICE in the SOCKS5 proxy

	log.Printf("Connection %s is up (addresses: %v, no default route)", conn.Name, addresses)
	return nil
}

func (m *Manager) parseWireGuardConfig(configPath string) (string, []string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", nil, err
	}

	var wgConfig strings.Builder
	var addresses []string
	lines := strings.Split(string(data), "\n")
	inInterface := false

	// Settings that wg-quick understands but wg doesn't
	interfaceOnlySettings := map[string]bool{
		"Address":    true,
		"DNS":        true,
		"MTU":        true,
		"Table":      true,
		"PreUp":      true,
		"PostUp":     true,
		"PreDown":    true,
		"PostDown":   true,
		"SaveConfig": true,
	}

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Handle section headers
		if trimmedLine == "[Interface]" {
			inInterface = true
			wgConfig.WriteString(line + "\n")
			continue
		}

		if strings.HasPrefix(trimmedLine, "[") {
			inInterface = false
			wgConfig.WriteString(line + "\n")
			continue
		}

		// Handle comments and empty lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") || strings.HasPrefix(trimmedLine, ";") {
			wgConfig.WriteString(line + "\n")
			continue
		}

		// Parse key-value pairs
		if strings.Contains(trimmedLine, "=") {
			parts := strings.SplitN(trimmedLine, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Special handling for Address field
				if inInterface && key == "Address" {
					// Parse addresses (can be comma-separated)
					addrList := strings.Split(value, ",")
					for _, addr := range addrList {
						addr = strings.TrimSpace(addr)
						if addr != "" {
							addresses = append(addresses, addr)
						}
					}
					// Don't add Address to WireGuard config
					continue
				}

				// Skip other interface-only settings
				if inInterface && interfaceOnlySettings[key] {
					log.Printf("Skipping interface-only setting: %s", key)
					continue
				}

				// Add all other settings to WireGuard config
				wgConfig.WriteString(line + "\n")
			} else {
				wgConfig.WriteString(line + "\n")
			}
		} else {
			wgConfig.WriteString(line + "\n")
		}
	}

	if len(addresses) == 0 {
		return "", nil, fmt.Errorf("no Address found in config")
	}

	return wgConfig.String(), addresses, nil
}

func (m *Manager) StartHealthChecks(ctx context.Context) {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	log.Printf("Starting health checks every %v", m.checkInterval)

	// Initial check
	for _, conn := range m.connections {
		go m.performHealthCheck(conn)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, conn := range m.connections {
				go m.performHealthCheck(conn)
			}
		}
	}
}

func (m *Manager) performHealthCheck(conn *Connection) {
	err := m.checkHealth(conn)
	now := time.Now().Unix()
	conn.lastCheck.Store(now)

	if err != nil {
		failures := conn.failureCount.Add(1)
		log.Printf("Health check failed for %s (failures: %d): %v", conn.Name, failures, err)

		if failures >= int32(m.failureThreshold) {
			if conn.healthy.Load() {
				log.Printf("Marking connection %s as unhealthy", conn.Name)
				conn.healthy.Store(false)
				m.stats.SetConnectionHealth(conn.Index, false)
			}
		}
	} else {
		conn.failureCount.Store(0)
		if !conn.healthy.Load() {
			log.Printf("Connection %s is now healthy", conn.Name)
			conn.healthy.Store(true)
			m.stats.SetConnectionHealth(conn.Index, true)
		}
	}
}

func (m *Manager) checkHealth(conn *Connection) error {
	// Use IP address directly instead of hostname to avoid DNS routing issues
	// when multiple WireGuard interfaces are active
	// We'll use Cloudflare's IP (1.1.1.1) for connectivity testing
	healthCheckIP := "1.1.1.1:443"
	healthCheckHost := "cloudflare.com"

	// Create a dialer that binds to the specific WireGuard interface
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var operr error
			err := c.Control(func(fd uintptr) {
				operr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, conn.InterfaceName)
			})
			if err != nil {
				return err
			}
			return operr
		},
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Override the address to use IP instead of hostname
			return dialer.DialContext(ctx, network, healthCheckIP)
		},
		TLSClientConfig: &tls.Config{
			ServerName: healthCheckHost,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Build the request with proper Host header
	req, err := http.NewRequest("GET", "https://"+healthCheckHost+"/cdn-cgi/trace", nil)
	if err != nil {
		return err
	}
	req.Host = healthCheckHost

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	m.stats.RecordLatency(conn.Index, latency)
	return nil
}

func (m *Manager) GetHealthyConnection(index int) (*Connection, error) {
	if index < 0 || index >= len(m.connections) {
		return nil, fmt.Errorf("invalid connection index: %d", index)
	}

	conn := m.connections[index]
	if !conn.healthy.Load() {
		return nil, fmt.Errorf("connection %s is not healthy", conn.Name)
	}

	return conn, nil
}

func (m *Manager) GetRandomHealthyConnection() (*Connection, error) {
	healthyConns := make([]*Connection, 0, len(m.connections))

	for _, conn := range m.connections {
		if conn.healthy.Load() {
			healthyConns = append(healthyConns, conn)
		}
	}

	if len(healthyConns) == 0 {
		return nil, fmt.Errorf("no healthy connections available")
	}

	// Simple round-robin for now (can be improved with actual randomness)
	idx := int(time.Now().UnixNano() % int64(len(healthyConns)))
	return healthyConns[idx], nil
}

func (m *Manager) GetConnections() []*Connection {
	return m.connections
}

func (m *Manager) Cleanup() {
	log.Println("Cleaning up WireGuard connections...")

	var wg sync.WaitGroup
	for _, conn := range m.connections {
		wg.Add(1)
		go func(c *Connection) {
			defer wg.Done()
			log.Printf("Bringing down connection: %s", c.Name)

			// Remove the interface
			cmd := exec.Command("ip", "link", "del", c.InterfaceName)
			if output, err := cmd.CombinedOutput(); err != nil {
				log.Printf("Error removing %s: %v (output: %s)", c.InterfaceName, err, output)
			}
		}(conn)
	}

	wg.Wait()
	log.Println("All connections cleaned up")
}

func (c *Connection) IsHealthy() bool {
	return c.healthy.Load()
}

func (c *Connection) GetLastCheck() time.Time {
	return time.Unix(c.lastCheck.Load(), 0)
}
