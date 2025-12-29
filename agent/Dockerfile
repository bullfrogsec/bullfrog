FROM golang:1.24.11-bookworm@sha256:fc58bb98c4b7ebc8211c94df9dee40489e48363c69071bceca91aa59023b0dee

ARG BUILDOS
ARG BUILDARCH
ARG BUILDNAME

WORKDIR /agent

RUN apt-get update
RUN apt-get install --yes libnetfilter-queue-dev

COPY . ./

RUN env GOOS=$BUILDOS GOARCH=$BUILDARCH go build -trimpath -ldflags=-buildid=
