FROM alpine:latest as certs
RUN apk --update add ca-certificates

FROM golang:1.13 AS builder
WORKDIR /go/src/github.com/aau-network-security/gollector
COPY ./go.mod ./
COPY ./go.sum ./
RUN go mod download
COPY ./ ./
WORKDIR /go/src/github.com/aau-network-security/gollector/app/ct
RUN GOOS=linux CGO_ENABLED=0 go build -o app .

FROM scratch
LABEL maintainer="Kaspar Hageman <kh@es.aau.dk>"
ENV VERSION 1.0
VOLUME /tmp
COPY --from=builder /go/src/github.com/aau-network-security/gollector/app/ct/app .
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["./app"]
