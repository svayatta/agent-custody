# The shared gateway as a container: `agent-custody gateway --http` on Node, one session per grant, for every agent
# on the host or cluster that points at it. Built two ways from the same file: a release installs the published npm
# package of AGENT_CUSTODY_VERSION; a build from main puts a tarball of the workspace package in pkg/ and installs
# that. Mounts: /config (read-only: gateway.json, policy.cedar or policy.rego, the principals' public keys) and /data (the gateway
# key, receipts, the local log, the revocation file). The opa binary is copied in from the official static image so a
# policy.rego compiles when the gateway loads it; Cedar policies and OPA servers do not use it.
FROM openpolicyagent/opa:1.22.4-static@sha256:12cecac5a174368f7d3f09d3a19d040ebe0c91d576e520335ae7a985a26e39d3 AS opa

FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5

COPY --from=opa /opa /usr/local/bin/opa

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
EXPOSE 8790 8791 8780

ENV DATA_DIR=/data \
    GATEWAY_CONFIG=/config/gateway.json \
    GATEWAY_PORT=8790 \
    EGRESS_PORT=8791 \
    DOOR_PORT=8780

# healthy when the gateway answers, or the egress witness or the door when the container runs in that mode
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${GATEWAY_PORT}/health" > /dev/null 2>&1 || wget -qO- "http://127.0.0.1:${EGRESS_PORT}/.well-known/agent-custody-egress" > /dev/null 2>&1 || wget -qO- "http://127.0.0.1:${DOOR_PORT}/.well-known/agent-custody-door" > /dev/null || exit 1

ENTRYPOINT ["gateway-entrypoint.sh"]
CMD ["serve"]
