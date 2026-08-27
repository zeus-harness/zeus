# syntax=docker/dockerfile:1.7

FROM caddy:2.10.2-alpine

# The upstream binary carries cap_net_bind_service, but Zeus listens on 8080.
# Strip it so the gateway can start with an empty capability bounding set.
RUN setcap -r /usr/bin/caddy

COPY infra/caddy/Caddyfile /etc/caddy/Caddyfile
