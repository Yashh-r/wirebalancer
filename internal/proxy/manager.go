package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/tomventa/wirebalancer/internal/config"
	"github.com/tomventa/wirebalancer/internal/stats"
	"github.com/tomventa/wirebalancer/internal/wireguard"
)

const (
	socks5Version = 0x05
	noAuth        = 0x00
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
	repSuccess    = 0x00
	repFailure    = 0x01
)

type Manager struct {
	cfg       config.ProxyConfig
	wgManager *wireguard.Manager
	stats     *stats.Tracker
	bufPool   *sync.Pool
}

func NewManager(cfg config.ProxyConfig, wgManager *wireguard.Manager, statsTracker *stats.Tracker) *Manager {
	return &Manager{
		cfg:       cfg,
		wgManager: wgManager,
		stats:     statsTracker,
		bufPool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, cfg.BufferSize)
				return &buf
			},
		},
	}
}

func (m *Manager) StartProxy(ctx context.Context, index int, port int) error {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on %s (index: %d)", addr, index)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		go m.handleConnection(ctx, conn, index)
	}
}

func (m *Manager) handleConnection(ctx context.Context, clientConn net.Conn, index int) {
	defer clientConn.Close()

	// Set deadlines
	if m.cfg.ReadTimeout > 0 {
		clientConn.SetReadDeadline(time.Now().Add(time.Duration(m.cfg.ReadTimeout) * time.Second))
	}

	// SOCKS5 handshake
	if err := m.handleHandshake(clientConn); err != nil {
		log.Printf("Handshake error: %v", err)
		return
	}

	// Get target address
	targetAddr, err := m.getTargetAddress(clientConn)
	if err != nil {
		log.Printf("Failed to get target address: %v", err)
		return
	}

	// Select WireGuard connection
	var wgConn *wireguard.Connection
	if index == 0 {
		// Random selection
		wgConn, err = m.wgManager.GetRandomHealthyConnection()
	} else {
		// Specific connection
		wgConn, err = m.wgManager.GetHealthyConnection(index - 1)
	}

	if err != nil {
		log.Printf("No healthy connection available: %v", err)
		m.sendConnectResponse(clientConn, repFailure)
		return
	}

	// Connect to target through WireGuard interface
	targetConn, err := m.dialThroughInterface(wgConn.InterfaceName, targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		m.sendConnectResponse(clientConn, repFailure)
		return
	}
	defer targetConn.Close()

	// Send success response
	if err := m.sendConnectResponse(clientConn, repSuccess); err != nil {
		log.Printf("Failed to send connect response: %v", err)
		return
	}

	// Update stats
	m.stats.IncrementRequests(wgConn.Index)

	// Relay data
	m.relay(clientConn, targetConn)
}

func (m *Manager) handleHandshake(conn net.Conn) error {
	buf := make([]byte, 257)

	// Read version and number of methods
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}

	if buf[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	nmethods := int(buf[1])
	if nmethods == 0 {
		return fmt.Errorf("no authentication methods")
	}

	// Read methods
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	// Send response: no authentication required
	_, err := conn.Write([]byte{socks5Version, noAuth})
	return err
}

func (m *Manager) getTargetAddress(conn net.Conn) (string, error) {
	buf := make([]byte, 4)

	// Read version, command, reserved, address type
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}

	if buf[0] != socks5Version {
		return "", fmt.Errorf("invalid version: %d", buf[0])
	}

	if buf[1] != cmdConnect {
		return "", fmt.Errorf("unsupported command: %d", buf[1])
	}

	atyp := buf[3]
	var addr string

	switch atyp {
	case atypIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", fmt.Errorf("read IPv4: %w", err)
		}
		addr = net.IP(ipBuf).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		addr = string(domainBuf)

	case atypIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", fmt.Errorf("read IPv6: %w", err)
		}
		addr = net.IP(ipBuf).String()

	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", addr, port), nil
}

func (m *Manager) sendConnectResponse(conn net.Conn, rep byte) error {
	response := []byte{
		socks5Version, // Version
		rep,           // Reply code
		0x00,          // Reserved
		atypIPv4,      // Address type
		0, 0, 0, 0,    // Bind address (0.0.0.0)
		0, 0, // Bind port (0)
	}
	_, err := conn.Write(response)
	return err
}

func (m *Manager) dialThroughInterface(interfaceName string, targetAddr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var operr error
			err := c.Control(func(fd uintptr) {
				operr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName)
			})
			if err != nil {
				return err
			}
			return operr
		},
	}

	return dialer.Dial("tcp", targetAddr)
}

func (m *Manager) relay(dst, src net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy from source to destination
	go func() {
		defer wg.Done()
		buf := m.bufPool.Get().(*[]byte)
		defer m.bufPool.Put(buf)
		io.CopyBuffer(dst, src, *buf)
		dst.(*net.TCPConn).CloseWrite()
	}()

	// Copy from destination to source
	go func() {
		defer wg.Done()
		buf := m.bufPool.Get().(*[]byte)
		defer m.bufPool.Put(buf)
		io.CopyBuffer(src, dst, *buf)
		src.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}
