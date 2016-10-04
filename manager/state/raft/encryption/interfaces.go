package encryption

// This package defines the interfaces and encryption package

// Decoder can decode data given the index, term, and data
type Decoder interface {
	Decode(index, term uint64, data []byte) ([]byte, error)
}

// Encoder can encode data using the index, term, and data
type Encoder interface {
	Encode(index, term uint64, data []byte) ([]byte, error)
}

type noopCoder struct{}

// Decode is a noop and never fails
func (n noopCoder) Decode(index, term uint64, data []byte) ([]byte, error) {
	return data, nil
}

// Encode is a noop and never fails
func (n noopCoder) Encode(index, term uint64, data []byte) ([]byte, error) {
	return data, nil
}

// Noop is a passthrough/noop Encoder and Decoder
var Noop = noopCoder{}
