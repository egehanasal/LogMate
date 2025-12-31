# LogMate - Multi-stage Docker build
#
# Build: docker build -t logmate .
# Run:   docker run -it logmate

# =============================================================================
# Stage 1: Build environment
# =============================================================================
FROM rust:1.83-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first (for better layer caching)
COPY Cargo.toml Cargo.lock ./
COPY crates/logmate-core/Cargo.toml crates/logmate-core/
COPY crates/logmate-ingestion/Cargo.toml crates/logmate-ingestion/
COPY crates/logmate-pipeline/Cargo.toml crates/logmate-pipeline/
COPY crates/logmate-modules/Cargo.toml crates/logmate-modules/
COPY crates/logmate-output/Cargo.toml crates/logmate-output/
COPY crates/logmate-cli/Cargo.toml crates/logmate-cli/

# Create dummy source files to build dependencies
RUN mkdir -p crates/logmate-core/src \
    crates/logmate-ingestion/src \
    crates/logmate-pipeline/src \
    crates/logmate-modules/src \
    crates/logmate-output/src \
    crates/logmate-cli/src \
    && echo "pub fn dummy() {}" > crates/logmate-core/src/lib.rs \
    && echo "pub fn dummy() {}" > crates/logmate-ingestion/src/lib.rs \
    && echo "pub fn dummy() {}" > crates/logmate-pipeline/src/lib.rs \
    && echo "pub fn dummy() {}" > crates/logmate-modules/src/lib.rs \
    && echo "pub fn dummy() {}" > crates/logmate-output/src/lib.rs \
    && echo "fn main() {}" > crates/logmate-cli/src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release 2>/dev/null || true

# Copy actual source code
COPY crates/ crates/
COPY config/ config/

# Touch source files to ensure rebuild
RUN touch crates/logmate-core/src/lib.rs \
    crates/logmate-ingestion/src/lib.rs \
    crates/logmate-pipeline/src/lib.rs \
    crates/logmate-modules/src/lib.rs \
    crates/logmate-output/src/lib.rs \
    crates/logmate-cli/src/main.rs

# Build the release binary
RUN cargo build --release

# =============================================================================
# Stage 2: Runtime environment
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r logmate && useradd -r -g logmate logmate

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/target/release/logmate /usr/local/bin/logmate

# Copy default configuration and set permissions
COPY --from=builder /build/config/docker.toml /etc/logmate/config.toml
RUN chmod 644 /etc/logmate/config.toml

# Create log directory with proper ownership
RUN mkdir -p /var/log/logmate && chown -R logmate:logmate /var/log/logmate /etc/logmate

# Switch to non-root user
USER logmate

# Expose default ports
# 9514 - TCP ingestion
# 9515 - UDP ingestion
# 9090 - Prometheus metrics
EXPOSE 9514/tcp 9515/udp 9090/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# Default command
ENTRYPOINT ["logmate"]
CMD ["--config", "/etc/logmate/config.toml"]
