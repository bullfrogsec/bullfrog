FROM golang:1.22-bookworm

ARG BUILDOS
ARG BUILDARCH
ARG BUILDNAME

WORKDIR /agent

RUN apt-get update
RUN apt-get install --yes libnetfilter-queue-dev

COPY . ./

RUN env GOOS=$BUILDOS GOARCH=$BUILDARCH go build -trimpath -ldflags=-buildid=
