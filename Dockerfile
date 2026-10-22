FROM node:22-bookworm-slim AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build
FROM golang:1.27.3-bookworm AS build
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /scanner ./cmd/local
RUN mkdir /data
FROM gcr.io/distroless/static-debian12:nonroot AS minimal
WORKDIR /app
COPY --from=web --chown=65532:65532 /dist ./dist
COPY --from=build /scanner /app/scanner
COPY --from=build --chown=65532:65532 /data /data
ENV V1FS_DATA_DIR=/data V1FS_WEB_DIR=/app/dist PORT=8095
VOLUME ["/data"]
EXPOSE 8095
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 CMD ["/app/scanner", "-healthcheck"]
ENTRYPOINT ["/app/scanner", "-supervise"]

# Optional shell-enabled variant: docker build --target bash -t scanner:bash .
FROM debian:bookworm-slim AS bash
RUN apt-get update && apt-get install -y --no-install-recommends bash ca-certificates curl procps \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 scanner \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /bin/bash scanner
WORKDIR /app
COPY --from=minimal /app/ /app/
COPY --from=build --chown=65532:65532 /data /data
ENV V1FS_DATA_DIR=/data V1FS_WEB_DIR=/app/dist PORT=8095
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8095
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 CMD ["/app/scanner", "-healthcheck"]
ENTRYPOINT ["/app/scanner", "-supervise"]

# Keep the default build shell-free.
FROM minimal AS production
