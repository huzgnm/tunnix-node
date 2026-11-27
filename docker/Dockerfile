# Runtime image built from release binaries (see .github/workflows/release.yml).
# The binary is a static musl build, so the image only needs CA certificates.
FROM gcr.io/distroless/static-debian12
ARG TARGETARCH
COPY --chmod=0755 dist/tunnix-node-linux-${TARGETARCH} /usr/local/bin/tunnix-node
VOLUME ["/etc/tunnix-node", "/var/lib/tunnix-node"]
ENTRYPOINT ["/usr/local/bin/tunnix-node"]
CMD ["server", "-c", "/etc/tunnix-node/config.json"]
