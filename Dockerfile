# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY static ./static
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -buildid=" -o /out/telemetry-server .

FROM busybox:1.37.0-musl AS healthcheck

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.description="Minimal hardened NetGoat telemetry runtime" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"
WORKDIR /app
COPY --from=healthcheck /bin/busybox /busybox
COPY --from=build --chown=nonroot:nonroot /out/telemetry-server /app/telemetry-server
USER nonroot:nonroot
EXPOSE 9091
ENV TELEMETRY_ADDR=0.0.0.0:9091 \
    GOMEMLIMIT=128MiB
HEALTHCHECK --interval=10s --timeout=3s --retries=8 --start-period=5s CMD ["/busybox", "sh", "-c", "/busybox wget -qO- \"http://127.0.0.1:${TELEMETRY_ADDR##*:}/health\""]
ENTRYPOINT ["/app/telemetry-server"]
