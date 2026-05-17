FROM python:3.11-slim

LABEL maintainer="AutoRecon"
LABEL description="Automated Reconnaissance & Vulnerability Scanner"

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nikto \
    nmap \
    dnsutils \
    curl \
    wget \
    git \
    golang-go \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || \
    wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
    -O /tmp/nuclei.zip && unzip /tmp/nuclei.zip -d /usr/local/bin/ && rm /tmp/nuclei.zip || true

ENV PATH="/root/go/bin:$PATH"

# Set workdir
WORKDIR /autorecon

# Copy project files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create output directory
RUN mkdir -p /autorecon/reports

# Make main.py executable
RUN chmod +x main.py

# Pull nuclei templates on first run
RUN nuclei -update-templates 2>/dev/null || true

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
