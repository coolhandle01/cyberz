# ---- base: system tools shared by all targets --------------------------------
FROM python:3.12-slim AS base

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

# ---- Go toolchain ------------------------------------------------------------
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

# ---- Go-based security tools -------------------------------------------------
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/tomnomnom/waybackurls@latest

# ---- testssl.sh --------------------------------------------------------------
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

WORKDIR /app

# Copy only the project metadata first so pip dependency layers are cached
# independently of source changes.
COPY pyproject.toml ./

# ---- prod: minimal runtime image ---------------------------------------------
FROM base AS prod

RUN pip install --no-cache-dir -e . || true
COPY . .
RUN pip install --no-cache-dir -e .

CMD ["python", "-m", "main"]

# ---- debug: dev deps + debugpy for VS Code remote attach ---------------------
FROM base AS debug

RUN pip install --no-cache-dir -e ".[dev]" || true
COPY . .
RUN pip install --no-cache-dir -e ".[dev]"

CMD ["python", "-m", "debugpy", \
     "--listen", "0.0.0.0:5678", \
     "--wait-for-client", \
     "-m", "main"]
