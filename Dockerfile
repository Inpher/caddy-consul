FROM caddy:2.4.6-builder AS builder

RUN go clean -modcache
RUN xcaddy build \
    --with github.com/inpher/caddy-consul@v0.0.9 \
    --with github.com/pteich/caddy-tlsconsul@v1.3.8 \
    --with github.com/caddy-dns/googleclouddns@v1.0.2

FROM caddy:2.4.6
COPY --from=builder /usr/bin/caddy /usr/bin/caddy