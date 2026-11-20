# Stage 1: Build the Go application
FROM golang:1.27-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum to download dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o main ./cmd/api

# Stage 2: Create the final image
FROM alpine:3.24

WORKDIR /app

# Install runtime packages and create an unprivileged application user.
RUN apk add --no-cache tzdata \
    && addgroup -S app \
    && adduser -S -G app app

# Copy the built binary from the builder stage
COPY --from=builder /app/main ./main

# Copy migrations
COPY migrations ./migrations

USER app

# Expose port 8080 to the outside world
EXPOSE 8080

# Liveness only: /healthcheck does not touch the database. PORT must be set in
# the container environment (the service requires it); busybox provides wget.
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/healthcheck" || exit 1

# The service migrates at startup unless RUN_MIGRATION=false.
ENTRYPOINT ["./main"]
