# Sample Dockerfile. Replace with whatever your app actually needs.
#
# The container's stdout / stderr is captured by bugpot and re-emitted
# through tracing, so write logs to fd 1 / 2 (no log files).
#
# Listen on the port declared in the ops repo's TOML — bugpot's
# router proxies HTTP to that port inside the container's netns.

FROM ghcr.io/static-debian12:latest

# Replace with your build output / runtime.
COPY ./server /server

EXPOSE 8080
ENTRYPOINT ["/server"]
