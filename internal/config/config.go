package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	WireGuard WireGuardConfig `yaml:"wireguard"`
	Proxy     ProxyConfig     `yaml:"proxy"`
	WebServer WebServerConfig `yaml:"webserver"`
}

type WireGuardConfig struct {
	Connections         []ConnectionConfig `yaml:"connections"`
	HealthCheckURL      string             `yaml:"health_check_url"`
	HealthCheckInterval int                `yaml:"health_check_interval"` // seconds
	FailureThreshold    int                `yaml:"failure_threshold"`
}

type ConnectionConfig struct {
	Name          string `yaml:"name"`
	InterfaceName string `yaml:"interface_name"`
	ConfigPath    string `yaml:"config_path"`
}

type ProxyConfig struct {
	BasePort        int `yaml:"base_port"` // 9930
	ReadTimeout     int `yaml:"read_timeout"`
	WriteTimeout    int `yaml:"write_timeout"`
	FailureHTTPCode int `yaml:"failure_http_code"` // 580
	BufferSize      int `yaml:"buffer_size"`
}

type WebServerConfig struct {
	Port int `yaml:"port"` // 9929
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Set defaults
	if cfg.WireGuard.HealthCheckURL == "" {
		// Use IP address instead of domain to avoid DNS resolution issues
		// This is Cloudflare's IP that returns trace info
		cfg.WireGuard.HealthCheckURL = "http://1.1.1.1/cdn-cgi/trace"
	}
	if cfg.WireGuard.HealthCheckInterval == 0 {
		cfg.WireGuard.HealthCheckInterval = 30
	}
	if cfg.WireGuard.FailureThreshold == 0 {
		cfg.WireGuard.FailureThreshold = 3
	}
	if cfg.Proxy.BasePort == 0 {
		cfg.Proxy.BasePort = 9930
	}
	if cfg.Proxy.ReadTimeout == 0 {
		cfg.Proxy.ReadTimeout = 30
	}
	if cfg.Proxy.WriteTimeout == 0 {
		cfg.Proxy.WriteTimeout = 30
	}
	if cfg.Proxy.FailureHTTPCode == 0 {
		cfg.Proxy.FailureHTTPCode = 580
	}
	if cfg.Proxy.BufferSize == 0 {
		cfg.Proxy.BufferSize = 32768 // 32KB
	}
	if cfg.WebServer.Port == 0 {
		cfg.WebServer.Port = 9929
	}

	return &cfg, nil
}
