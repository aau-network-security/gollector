FROM golang:1.13 AS builder
WORKDIR /go/src/github.com/aau-network-security/gollector
COPY ./ ./
WORKDIR /go/src/github.com/aau-network-security/gollector/app/offline
RUN go get ./...
RUN GOOS=linux CGO_ENABLED=0 go build -o app .

FROM scratch
LABEL maintainer="Gian Marco Mennecozzi <gmm@es.aau.dk>"
COPY --from=builder /go/src/github.com/aau-network-security/gollector/app/offline/app .

ENTRYPOINT ["./app"]