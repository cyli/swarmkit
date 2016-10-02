package encryption

// This package defines the interfaces and encryption package

// Coder comment here
type decoder interface {
	Decode(index, term uint64, data []byte) ([]byte, error)
	ID() string
}

type encoder interface {
	Encode(index, term uint64, data []byte) ([]byte, error)
	ID() string
}
