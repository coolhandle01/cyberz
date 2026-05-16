FROM python:3.12-slim

# ---- system packages --------------------------------------------------------
# nmap: TCP connect scans (recon/nmap.py)
# sqlmap: SQL injection (pentest/sqlmap.py)
# curl + ca-certificates: runtime HTTP + TLS; also used by install scripts
# git: cloning testssl.sh
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        nmap \
        sqlmap \
        curl \
        ca-certificates \
        git \
        procps \
    && rm -rf /var/lib/apt/lists/*

# ---- Go toolchain -----------------------------------------------------------
ENV GO_VERSION=1.23.4
ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"

RUN arch="$(uname -m)" && \
    case "${arch}" in \
        x86_64)  arch="amd64" ;; \
        aarch64) arch="arm64" ;; \
        *) echo "Unsupported arch: ${arch}" && exit 1 ;; \
    esac && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" \
        -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

# ---- Go-based security tools ------------------------------------------------
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/tomnomnom/waybackurls@latest

# ---- testssl.sh -------------------------------------------------------------
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# ---- Python application ------------------------------------------------------
WORKDIR /app

COPY pyproject.toml ./
# Install deps first so the layer is cached when only source changes
RUN pip install --no-cache-dir -e ".[dev]" || true

# debugpy for VS Code remote debugging (attach on port 5678)
RUN pip install --no-cache-dir debugpy

# Source is volume-mounted at runtime in docker-compose so edits are live.
# We still copy it here so the image is self-contained for CI builds.
COPY . .
RUN pip install --no-cache-dir -e ".[dev]"

# ---- entrypoint -------------------------------------------------------------
# Default: launch with debugpy waiting for an attach.
# Override CMD in docker-compose or on the CLI for unattended runs.
#
# The --wait-for-client flag means the pipeline will not start until a
# debugger (VS Code) attaches. Remove it for unattended runs:
#   docker compose run cybersquad python main.py
CMD ["python", "-m", "debugpy", \
     "--listen", "0.0.0.0:5678", \
     "--wait-for-client", \
     "-m", "main"]
