# Stage 1: Build the Go application
FROM golang:1.27.2-alpine3.24 AS builder

WORKDIR /app

# Copy go.mod and go.sum to download dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Stage 2: Create the final image
FROM alpine:3.24

WORKDIR /app

# Install runtime packages and create an unprivileged application user.
RUN apk add --no-cache tzdata \
    && addgroup -S app \
    && adduser -S -G app app

# Copy the built binary from the builder stage
COPY --from=builder /app/main ./main
COPY entrypoint.sh ./entrypoint.sh

# Copy migrations
COPY migrations ./migrations

# Ensure entrypoint is executable
RUN chmod +x ./entrypoint.sh

USER app

# Expose port 8080 to the outside world
EXPOSE 8080

# Optional migration can be toggled via RUN_MIGRATION=true
ENTRYPOINT ["./entrypoint.sh"]
