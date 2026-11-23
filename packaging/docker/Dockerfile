# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
ARG VERSION=0.1.0-beta.2
FROM ghcr.io/linuxserver/baseimage-ubuntu:resolute@sha256:e044df9763cfadf3081e6b7a2e949809661c9e751b6ce65040075972c9b35587

ARG VERSION
ARG TARGETARCH
LABEL org.opencontainers.image.title="eMuleBB Rust" \
      io.emulebb.image.variant="ubuntu" \
      org.opencontainers.image.source="https://github.com/emulebb/emulebb-rust" \
      org.opencontainers.image.version="${VERSION}"

ENV HOME=/config \
    XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/config

# The pinned base can predate Ubuntu security fixes. Refresh its installed
# packages before adding the daemon; the release SBOM records resolved versions.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY dist/emulebb-rust-v${VERSION}-linux-${TARGETARCH}.deb /tmp/emulebb-rust.deb
RUN dpkg-deb -x /tmp/emulebb-rust.deb / && rm /tmp/emulebb-rust.deb
COPY root/ /
RUN chmod 755 /etc/s6-overlay/s6-rc.d/svc-emulebb-rust/run \
    /usr/lib/emulebb-rust/emulebb-profile-init \
    /usr/local/bin/emulebb-rust-healthcheck

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/usr/local/bin/emulebb-rust-healthcheck"]
EXPOSE 20017/tcp 20019/tcp 20020/udp
VOLUME /config /data
