FROM python:3.11-slim

WORKDIR /app

# Install dependencies first for layer caching. The second line is the
# [explorer] extra of pyproject.toml (Heimdall), so that the same image runs
# a node or the explorer (tests/test_devnet_bootstrap.py keeps them equal).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir "fastapi>=0.141.1" "uvicorn[standard]>=0.53.0" "httpx>=0.28.1" "jinja2>=3.1.6"

# Copy the rest of the source.
COPY kern/ ./kern/
COPY kern_explorer/ ./kern_explorer/
COPY scripts/ ./scripts/

# At container start, the entrypoint expects:
#   /data       — node data directory (mount a volume)
#   /genesis.json — genesis file (mount or build into image)
#   /keys       — baker keys (mount)
EXPOSE 8732 9732

# Inside a container the RPC must listen on every interface for a published
# port to reach it (the node's own default is 127.0.0.1). Publish it on the
# host's loopback only, for example `-p 127.0.0.1:8732:8732`.
ENTRYPOINT ["python", "-m", "kern.node"]
CMD ["start", "--data-dir", "/data", "--rpc-port", "8732", "--rpc-bind", "0.0.0.0", "--p2p-port", "9732"]
