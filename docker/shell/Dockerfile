# StarClaw shell image (tools.shell). Built by `starclaw shell build`; the BUILD may use the network, the running container never does.
# Base pinned by digest (same node:25.9-slim digest as the code sandbox). apt packages are NOT version-pinned: they float at build time (see SECURITY.md).
FROM node@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370

ARG DOCKERFILE_SHA256=unset
LABEL org.opencontainers.image.title="starclaw-shell" \
      starclaw.shell.dockerfile.sha256="${DOCKERFILE_SHA256}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends git python3 jq patch unzip zip ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && (find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true)

ENV HOME=/tmp \
    LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    GIT_CONFIG_NOSYSTEM=1 \
    NODE_ENV=production

# Unprivileged user (nobody). The base entrypoint script is not used.
USER 65534:65534
WORKDIR /work
ENTRYPOINT []
CMD []
