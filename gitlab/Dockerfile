FROM ubuntu:16.04

ADD envoy /envoy

ENTRYPOINT ["/envoy"]
CMD ["-c", "/config/config.json", "-l", "trace", "--base-id", "666"]
