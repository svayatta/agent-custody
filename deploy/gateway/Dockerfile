# The shared gateway as a container: `agent-custody gateway --http` on Node, one session per grant, for every agent
# on the host or cluster that points at it. Built two ways from the same file: a release installs the published npm
# package of AGENT_CUSTODY_VERSION; a build from main puts a tarball of the workspace package in pkg/ and installs
# that. Mounts: /config (read-only: gateway.json, policy.cedar, the principals' public keys) and /data (the gateway
# key, receipts, the local log, the revocation file).
FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f

ARG AGENT_CUSTODY_VERSION
COPY pkg/ /tmp/pkg/
RUN if ls /tmp/pkg/*.tgz > /dev/null 2>&1; then npm install -g /tmp/pkg/*.tgz; else npm install -g "@agent-custody/receipts@${AGENT_CUSTODY_VERSION:?pass --build-arg AGENT_CUSTODY_VERSION=<version>, or put a tarball in pkg/}"; fi \
  && rm -rf /tmp/pkg \
  && adduser -D -u 10001 custody \
  && mkdir -p /config /data/keys \
  && chown -R custody:custody /data

COPY gateway-entrypoint.sh /usr/local/bin/gateway-entrypoint.sh
RUN chmod +x /usr/local/bin/gateway-entrypoint.sh

USER custody
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8790

ENV DATA_DIR=/data \
    GATEWAY_CONFIG=/config/gateway.json \
    GATEWAY_PORT=8790

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${GATEWAY_PORT}/health" > /dev/null || exit 1

ENTRYPOINT ["gateway-entrypoint.sh"]
CMD ["serve"]
