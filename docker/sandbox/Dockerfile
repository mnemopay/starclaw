# StarClaw sandbox image. Built by `starclaw sandbox build`, which copies the package's runner.cjs next to this file.
# Base pinned by digest (node:25.9-slim == node:25-slim, Node v25.9.0). Re-resolve and update deliberately.
FROM node@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370

ARG RUNNER_SHA256=unset
LABEL org.opencontainers.image.title="starclaw-sandbox" \
      starclaw.runner.sha256="${RUNNER_SHA256}"

# Root-owned, read-only, not writable by the runtime user.
RUN mkdir -p /sandbox && chown 0:0 /sandbox && chmod 0555 /sandbox
COPY --chown=0:0 --chmod=0444 runner.cjs /sandbox/runner.cjs

ENV NODE_ENV=production
# Unprivileged user (nobody). The base image's entrypoint script is not used.
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT []
CMD []
