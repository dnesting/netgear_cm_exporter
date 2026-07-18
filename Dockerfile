FROM golang:1.25 AS build

WORKDIR /src
COPY . .

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG LDFLAGS

RUN go env -w GOARCH=$(echo $TARGETPLATFORM | cut -d / -f2)
RUN go env -w GOOS=$(echo $TARGETPLATFORM | cut -d / -f1)
# Static binary: the runtime image is musl (alpine), so a glibc-linked
# binary (cgo default on native builds) fails with
# `exec /netgear_cm_exporter: no such file or directory` (missing
# /lib64/ld-linux-*.so interpreter). Cross-compiled arches got this for
# free (cgo auto-off); the native arch did not.
RUN go env -w CGO_ENABLED=0

RUN go mod download
RUN go build -ldflags "${LDFLAGS}" -o netgear_cm_exporter

FROM alpine:3.13
COPY --from=build /src/netgear_cm_exporter /netgear_cm_exporter

ENTRYPOINT ["/netgear_cm_exporter"]
