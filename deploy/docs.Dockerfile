# docs.agent-custody.dev: the site built from this checkout and served as static files. Build context is the
# repository root (the compose file sets it); the image carries only the built pages and a Caddy serving them.
FROM oven/bun:1@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d AS build
WORKDIR /src
COPY . .
RUN bun install --frozen-lockfile --ignore-scripts && bun run site:build

FROM caddy:2-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
COPY --from=build /src/site/.vitepress/dist /srv
COPY deploy/docs.Caddyfile /etc/caddy/Caddyfile
