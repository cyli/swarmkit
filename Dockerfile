FROM golang:1.8.3
RUN apt-get update -yq && apt-get install -yq build-essential
COPY . /go/src/github.com/docker/swarmkit
WORKDIR /go/src/github.com/docker/swarmkit
