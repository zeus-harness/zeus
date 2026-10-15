FROM docker.io/library/alpine:3.24.1 AS toolchain
COPY apk /packages
RUN apk --repositories-file /packages/repositories add --no-network busybox ca-certificates git nodejs npm pnpm python3 py3-pip rust cargo build-base bash \
    && mkdir -p /workspace /run /tmp \
    && touch /run/zeus-script \
    && apk info -v > /toolchain-packages.txt \
    && rm -rf /packages /var/cache/apk/*

FROM docker.io/library/alpine:3.24.1 AS adapter
COPY apk /packages
RUN apk --repositories-file /packages/repositories add --no-network python3 bubblewrap util-linux libseccomp-dev build-base \
    && rm -rf /packages /var/cache/apk/*
COPY sandbox/seccomp.c /tmp/seccomp.c
RUN cc -O2 /tmp/seccomp.c -lseccomp -o /tmp/seccomp \
    && mkdir -p /opt/zeus && /tmp/seccomp > /opt/zeus/seccomp.bpf \
    && rm /tmp/seccomp /tmp/seccomp.c
COPY --from=toolchain / /opt/zeus/rootfs/
COPY sandbox/broker.py sandbox/child.py /opt/zeus/
EXPOSE 8090
ENTRYPOINT ["/usr/bin/python3", "/opt/zeus/broker.py"]
