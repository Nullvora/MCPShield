# MCPShield container — static config scanning and remote (HTTP) live scanning.
#   docker build -t mcpshield .
#   docker run --rm -v "$PWD:/work" mcpshield scan --project /work
# (Live-scanning stdio servers needs their runtimes — node/npx, uv — inside the container; extend this image if required.)
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY mcpshield ./mcpshield
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="MCPShield" \
      org.opencontainers.image.description="Security scanner and runtime guard for Model Context Protocol (MCP)" \
      org.opencontainers.image.source="https://github.com/Nullvora/MCPShield" \
      org.opencontainers.image.vendor="Nullvora" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl \
 && useradd --create-home --uid 10001 shield
USER shield
WORKDIR /work
ENTRYPOINT ["mcpshield"]
CMD ["--help"]
