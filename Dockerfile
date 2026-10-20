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
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=web --chown=65532:65532 /dist ./dist
COPY --from=build /scanner /app/scanner
COPY --from=build --chown=65532:65532 /data /data
ENV V1FS_DATA_DIR=/data V1FS_WEB_DIR=/app/dist PORT=8095
VOLUME ["/data"]
EXPOSE 8095
ENTRYPOINT ["/app/scanner"]
