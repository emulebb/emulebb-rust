# syntax=docker/dockerfile:1
ARG VERSION=0.1.0-beta.2
FROM lscr.io/linuxserver/baseimage-ubuntu:noble@sha256:94a6c41cbd36a3cdc38cf1f6d3ffd376e9349aabf8d9bbc825112e1a49f6c330

ARG VERSION
ARG TARGETARCH
LABEL org.opencontainers.image.title="eMuleBB Rust" \
      org.opencontainers.image.source="https://github.com/emulebb/emulebb-rust" \
      org.opencontainers.image.version="${VERSION}"

ENV HOME=/config \
    XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/config

COPY dist/emulebb-rust-v${VERSION}-linux-${TARGETARCH}.deb /tmp/emulebb-rust.deb
RUN dpkg-deb -x /tmp/emulebb-rust.deb / && rm /tmp/emulebb-rust.deb
COPY root/ /
RUN chmod 755 /etc/s6-overlay/s6-rc.d/svc-emulebb-rust/run \
    /usr/local/bin/emulebb-rust-healthcheck

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/usr/local/bin/emulebb-rust-healthcheck"]
EXPOSE 4711/tcp 4662/tcp 4672/udp
VOLUME /config /data
