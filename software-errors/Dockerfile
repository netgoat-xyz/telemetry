# syntax=docker/dockerfile:1

FROM gcr.io/distroless/nodejs22-debian13:nonroot
LABEL org.opencontainers.image.description="Minimal hardened NetGoat software error monitor runtime" \
      org.opencontainers.image.base.name="gcr.io/distroless/nodejs22-debian13:nonroot"
WORKDIR /app
COPY --chown=nonroot:nonroot server.mjs ./
COPY --chown=nonroot:nonroot static ./static
USER nonroot:nonroot
EXPOSE 9092
ENV HOST=0.0.0.0 \
    PORT=9092
HEALTHCHECK --interval=10s --timeout=3s --retries=8 --start-period=5s CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:9092/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["server.mjs"]
