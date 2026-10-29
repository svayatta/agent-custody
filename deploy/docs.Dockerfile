# docs.agent-custody.dev: the site built from this checkout and served as static files. Build context is the
# repository root (the compose file sets it); the image carries only the built pages and a Caddy serving them.
FROM oven/bun:1@sha256:ec06c3b6cea04192ae6770c434f668ca41d343ad19fa6472216c7b48be39c598 AS build
WORKDIR /src
COPY . .
RUN bun install --frozen-lockfile --ignore-scripts && bun run site:build

FROM caddy:2-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f
COPY --from=build /src/site/.vitepress/dist /srv
COPY deploy/docs.Caddyfile /etc/caddy/Caddyfile
