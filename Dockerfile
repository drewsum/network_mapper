# One image for every role (api / collector / migrate / seed); compose picks the command.

FROM node:24-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.11.17 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1
WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/ ./
RUN uv sync --frozen --no-dev

COPY --from=web /web/dist /app/web-dist
ENV NETMAP_WEB_DIST_DIR=/app/web-dist

# The collector's raw ARP socket needs CAP_NET_RAW, but Docker only grants cap_add
# capabilities to root. This copy of the interpreter carries it as a file capability and is
# used by the collector alone; the API and the other roles run the plain interpreter.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin  && cp "$(readlink -f /app/.venv/bin/python)" /app/.venv/bin/python-netraw  && setcap cap_net_raw+ep /app/.venv/bin/python-netraw  && apt-get purge -y libcap2-bin && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 netmap
USER netmap
EXPOSE 8000
CMD ["netmap", "api"]
