FROM python:3.11-slim

WORKDIR /app

# Install dependencies first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the source.
COPY kern/ ./kern/
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
