package encryption

import (
	"bytes"
	"fmt"
)

// Common test utilities

type meowCoder struct {
	// only take encoding failures - decode failures can happen if the bytes
	// do not have a cat
	encodeFailures map[string]struct{}
}

func (m *meowCoder) Encode(index, term uint64, orig []byte) ([]byte, error) {
	if _, ok := m.encodeFailures[fmt.Sprintf("%d_%d", index, term)]; ok {
		return nil, fmt.Errorf("refusing to encode")
	}
	return append(orig, []byte("🐱")...), nil
}

func (m *meowCoder) Decode(index, term uint64, orig []byte) ([]byte, error) {
	if !bytes.HasSuffix(orig, []byte("🐱")) {
		return nil, fmt.Errorf("not meowcoded")
	}
	return bytes.TrimSuffix(orig, []byte("🐱")), nil
}
