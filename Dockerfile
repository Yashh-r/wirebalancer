# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o wirebalancer \
    .

# Runtime stage
FROM alpine:latest

# Install WireGuard tools and dependencies
RUN apk add --no-cache \
    wireguard-tools \
    wireguard-tools-wg-quick \
    iptables \
    ip6tables \
    bash \
    ca-certificates \
    tzdata \
    openresolv \
    && rm -rf /var/cache/apk/*

# Install a minimal init system to handle resolvconf
RUN apk add --no-cache tini

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/wirebalancer /app/wirebalancer

# Copy configuration example
COPY config.example.yml /app/config.example.yml

# Create directory for WireGuard configs with proper permissions
RUN mkdir -p /etc/wireguard && \
    chmod 700 /etc/wireguard

# Create a script to fix WireGuard config permissions on startup
RUN echo '#!/bin/bash' > /app/fix-permissions.sh && \
    echo 'if [ -d /etc/wireguard ]; then' >> /app/fix-permissions.sh && \
    echo '    chmod 700 /etc/wireguard' >> /app/fix-permissions.sh && \
    echo '    chmod 600 /etc/wireguard/*.conf 2>/dev/null || true' >> /app/fix-permissions.sh && \
    echo 'fi' >> /app/fix-permissions.sh && \
    chmod +x /app/fix-permissions.sh

# WireGuard requires NET_ADMIN capability
# The container must be run with --cap-add=NET_ADMIN and privileged mode

# Expose ports
# 9929: Web dashboard
# 9930: Random proxy
# 9931+: Specific connection proxies
EXPOSE 9929 9930 9931 9932 9933 9934 9935 9936 9937 9938 9939 9940

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9929/health || exit 1

# Use tini to handle init process
ENTRYPOINT ["/sbin/tini", "--"]

# Fix permissions and start the application
CMD ["/bin/bash", "-c", "/app/fix-permissions.sh && /app/wirebalancer -config /app/config.yml"]