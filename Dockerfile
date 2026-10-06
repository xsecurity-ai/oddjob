# Oddjob — one image serving the API and the built UI.
#
# The backend serves `frontend/dist` itself, so there is no second
# container and no reverse proxy to configure. The path matters: the
# app resolves the UI as `<repo>/frontend/dist` relative to its own
# module, so the layout inside the image mirrors the repository.

# ---------------------------------------------------------------- UI
FROM node:22-alpine AS ui
WORKDIR /build/frontend

# Dependencies first: this layer is rebuilt only when the lockfile
# changes, which is what keeps an edit to one .tsx file off the
# critical path.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


# --------------------------------------------------------- jaws agents
# The agent binaries the UI hands out when deploying a Jaws. Built here
# so an operator can download one from the Oddjob they are already
# logged into, rather than being sent to find a release elsewhere and
# having to trust whatever they find.
#
# All six targets, because the host an agent is needed on is whatever
# the client has. Static (CGO_ENABLED=0) so they run on the older glibc
# they will meet in the field.
FROM golang:1.26-alpine AS jaws
WORKDIR /build/jaws

COPY jaws/go.mod jaws/go.sum ./
RUN go mod download

COPY jaws/ ./
RUN set -eu; \
    for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 \
             windows/amd64 windows/arm64; do \
      os="${t%/*}"; arch="${t#*/}"; \
      out="dist/jaws-$os-$arch"; \
      [ "$os" = windows ] && out="$out.exe"; \
      CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
        go build -trimpath -ldflags "-s -w" -o "$out" ./cmd/jaws; \
    done; \
    ls -l dist/


# ------------------------------------------------------- python deps
# A separate stage purely so `uv` (45 MB) and its caches do not ship.
FROM python:3.13-slim AS deps

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /src
COPY backend/pyproject.toml backend/uv.lock ./
# --no-install-project so this layer depends only on the lockfile.
RUN uv sync --locked --no-dev --no-install-project


# ------------------------------------------------------------ runtime
FROM python:3.13-slim AS runtime

# libpq for psycopg, curl for the healthcheck. No build toolchain: the
# wheels are prebuilt, and leaving a compiler in a production image is
# a gift to anyone who gets a shell in it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq5 curl \
 && rm -rf /var/lib/apt/lists/*

# Created before anything is copied in. Copying first and then running
# `chown -R` writes a second copy of the whole virtualenv into a new
# layer — that alone was 228 MB of this image.
RUN useradd --system --uid 10001 --create-home --home-dir /app oddjob

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

COPY --from=deps --chown=oddjob:oddjob /opt/venv /opt/venv
COPY --chown=oddjob:oddjob backend/ /app/backend/
COPY --from=ui --chown=oddjob:oddjob /build/frontend/dist /app/frontend/dist
COPY --from=jaws --chown=oddjob:oddjob /build/jaws/dist /app/jaws-dist
COPY --chown=oddjob:oddjob docker/entrypoint.sh /usr/local/bin/entrypoint.sh

# `data` holds the session-signing key, which has to outlive the
# container or every restart logs everyone out — people respond to
# that by keeping a long-lived token lying around instead.
RUN mkdir -p /app/backend/data && chown oddjob:oddjob /app/backend/data \
 && chmod +x /usr/local/bin/entrypoint.sh

USER oddjob
WORKDIR /app/backend

ENV ODDJOB_SECRET_FILE=/app/backend/data/.secret \
    PORT=8000

EXPOSE 8000

# Start-period is generous: the first boot runs migrations, and a
# container killed for being "unhealthy" while migrating is worse than
# one that takes a minute to settle.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PORT}/api/auth/setup-required" || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
