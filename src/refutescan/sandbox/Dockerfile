# refutescan — sandbox image.
#
# A minimal jail the scanner runs each audit inside. It does NOT run a service;
# the host starts it with `sleep` and drives it via `docker exec ... python
# /toolrunner.py`. Two uses, same image:
#   • fetch container — `git clone` an untrusted URL (network on, no host mounts)
#   • audit container — read the repo via the toolrunner (--network none, ro)
# Only git + the Python stdlib are needed.
FROM python:3.12-alpine

RUN apk add --no-cache git \
    && adduser -D -u 10001 scanner

# Hardened git defaults baked in (belt-and-suspenders with the runtime flags the
# host passes): never run repo-supplied hooks, no fsmonitor command execution,
# and refuse the ext::/fd:: transports that can run shell commands.
RUN git config --system core.hooksPath /dev/null \
    && git config --system core.fsmonitor false \
    && git config --system protocol.ext.allow never \
    && git config --system protocol.fd.allow never

COPY toolrunner.py /toolrunner.py

USER scanner
WORKDIR /work
ENTRYPOINT []
