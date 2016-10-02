package encryption

//go:generate protoc -I.:/usr/local --gogoswarm_out=import_path=github.com/docker/swarmkit/manager/state/raft/encryption,Mgoogle/protobuf/descriptor.proto=github.com/gogo/protobuf/protoc-gen-gogo/descriptor:. wrapper.proto
