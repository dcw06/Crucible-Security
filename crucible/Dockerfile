FROM golang:1.23-bookworm AS osv-builder
RUN go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.3.8

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (semgrep needs these)
RUN apt-get update && apt-get install -y \
    clamav \
    nodejs \
    default-jdk-headless \
    clang \
    curl \
    dumb-init \
    git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=osv-builder /go/bin/osv-scanner /usr/local/bin/osv-scanner

# Install Python dependencies
COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -c constraints.txt -r requirements.txt

# Copy source
COPY . .

# Default command (overridden by docker-compose per service)
ENV PORT=8501
RUN chmod +x start.sh
RUN useradd --create-home --uid 10001 crucible \
    && mkdir -p /var/lib/crucible /var/lib/crucible-scratch \
    && chown -R crucible:crucible \
        /app /var/lib/clamav /var/lib/crucible /var/lib/crucible-scratch
USER 10001:10001
ENTRYPOINT ["dumb-init", "--"]
CMD ["./start.sh"]
