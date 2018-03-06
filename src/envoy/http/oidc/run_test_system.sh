#!/usr/bin/env bash
set -e
bazel build //src/envoy:envoy
# Run envoy with xsrf, oidc and auth filters enabled
mkdir -p /tmp/envoy
# Create a directory that has a TLS signing key and certificate
mkdir -p tls
openssl req -nodes -x509 -newkey rsa:2048 -keyout tls/server.key -out tls/server.cert -days 365 -subj "/CN=acme" \
## Run envoy
bazel-bin/src/envoy/envoy -c src/envoy/http/oidc/config/envoy.json -l trace > /tmp/envoy/envoy.log 2> >(tee /tmp/envoy/envoy.err >&2)&
## Run an echo service behind envoy
go run test/backend/echo/echo.go > /tmp/envoy/echo.log 2> >(tee /tmp/envoy/echo.err >&2) &
## Run SPA
test -d ../spa/example
cd ../spa/example && ng serve --open --disable-host-check --proxy=proxy.conf.json > /tmp/envoy/spa.log 2> >(tee /tmp/envoy/spa.err >&2)
