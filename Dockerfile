FROM --platform=$BUILDPLATFORM golang:1.19 AS build

WORKDIR /src
COPY . .

ARG TARGETPLATFORM
ARG BUILDPLATFORM

RUN go env -w GOARCH=$(echo $TARGETPLATFORM | cut -d / -f2)
RUN go env -w GOOS=$(echo $TARGETPLATFORM | cut -d / -f1)
RUN go mod download
RUN go build -o netgear_cm_exporter

FROM --platform=$TARGETPLATFORM alpine:3.13
COPY --from=build /src/netgear_cm_exporter /netgear_cm_exporter

ENTRYPOINT ["/netgear_cm_exporter"]
