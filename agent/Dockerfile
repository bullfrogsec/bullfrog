FROM golang:1.22.7-bookworm@sha256:027bd04b1d3b4529bf8ccebf62eb7eeeae7b7bef134a68bd419824e929ad93ad

ARG BUILDOS
ARG BUILDARCH
ARG BUILDNAME

WORKDIR /agent

RUN apt-get update
RUN apt-get install --yes libnetfilter-queue-dev

COPY . ./

RUN env GOOS=$BUILDOS GOARCH=$BUILDARCH go build -trimpath -ldflags=-buildid=
