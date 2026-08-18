# linebreak-gate MCP server (stdio)
# https://github.com/Baktun-Studio/linebreak-gate — Apache-2.0
#
# Serves a repository's human-approved spec (.linebreak/spec/) to MCP clients
# over stdio, read-only and fully offline. Mount the project to inspect and
# point the server at it, e.g.:
#
#   docker run -i --rm -v /path/to/repo:/path/to/repo IMAGE --path /path/to/repo

FROM python:3.12-slim

# Reproducible: pin the exact released version from PyPI.
ARG LINEBREAK_GATE_VERSION=1.10.4

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# cryptography is pinned <47: the 47+ manylinux aarch64 wheels use CPU
# features that SIGILL under some virtualized arm64 environments (e.g.
# Docker Desktop VMs). 42..46 satisfy linebreak-gate's `cryptography>=42`.
RUN pip install --no-cache-dir "linebreak-gate==${LINEBREAK_GATE_VERSION}" "cryptography<47"

# Run as a non-root user.
RUN useradd --create-home --uid 1000 gate
USER gate
WORKDIR /home/gate

# MCP stdio server. Additional args (e.g. --path /project) are appended by
# the runtime; default project root is the working directory.
ENTRYPOINT ["linebreak-gate", "mcp"]
