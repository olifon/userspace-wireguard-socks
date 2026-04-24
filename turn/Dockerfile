FROM golang:1.25-alpine AS builder
RUN apk add --no-cache ca-certificates git
WORKDIR /src

COPY turn/go.mod turn/go.sum ./
COPY third_party/anet /third_party/anet
COPY third_party/pionturnv4 /third_party/pionturnv4
RUN go mod download

COPY turn/. .

RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/turn .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
WORKDIR /app

COPY --from=builder /out/turn /app/turn
COPY turn/docker-entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

VOLUME ["/config"]
EXPOSE 3478/udp 3478/tcp

ENV TURN_CONFIG_FILE=/config/turn.yaml

ENTRYPOINT ["/entrypoint.sh"]
