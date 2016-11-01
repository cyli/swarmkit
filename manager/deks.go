package manager

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/docker/swarmkit/ca"
	"github.com/docker/swarmkit/manager/encryption"
)

const (
	// the raft DEK (data encryption key) is stored in the TLS key as a header
	// these are the header values
	pemHeaderRaftDEK              = "raft-dek"
	pemHeaderRaftPendingDEK       = "raft-dek-pending"
	pemHeaderRaftDEKNeedsRotation = "raft-dek-needs-rotation"
)

// RaftDEKData contains all the data stored in TLS pem headers
type RaftDEKData struct {
	CurrentDEK    []byte
	PendingDEK    []byte
	NeedsRotation bool
}

// RaftDEKPEMHeadersManager manages the raft DEK headers on a TLS Key
type RaftDEKPEMHeadersManager struct {
	mu        sync.Mutex
	data      RaftDEKData
	cachedKEK []byte
}

// NewRaftDEKPEMHeadersManager creates a new RaftDEKPEMHeadersManager given some data to start with
func NewRaftDEKPEMHeadersManager(data RaftDEKData, kek []byte) *RaftDEKPEMHeadersManager {
	if data.CurrentDEK == nil {
		data.CurrentDEK = encryption.GenerateSecretKey()
	}
	return &RaftDEKPEMHeadersManager{
		data:      data,
		cachedKEK: kek,
	}
}

// SetCurrentHeaders loads the state of the DEK manager given the current TLS headers
func (r *RaftDEKPEMHeadersManager) SetCurrentHeaders(headers map[string]string, kek []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data := RaftDEKData{}
	var err error

	if currentDEKStr, ok := headers[pemHeaderRaftDEK]; ok {
		data.CurrentDEK, err = decodePEMHeaderValue(currentDEKStr, kek)
		if err != nil {
			return err
		}
	}
	if pendingDEKStr, ok := headers[pemHeaderRaftPendingDEK]; ok {
		data.PendingDEK, err = decodePEMHeaderValue(pendingDEKStr, kek)
		if err != nil {
			return err
		}
	}

	if data.PendingDEK != nil && data.CurrentDEK == nil {
		return fmt.Errorf("there is a pending DEK, but no current DEK")
	}

	_, data.NeedsRotation = headers[pemHeaderRaftDEKNeedsRotation]
	r.data = data
	r.cachedKEK = kek
	return nil
}

// GetNewHeaders returns new headers given the current KEK
func (r *RaftDEKPEMHeadersManager) GetNewHeaders(kek []byte) (map[string]string, func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	headers := make(map[string]string)
	for headerKey, contents := range map[string][]byte{
		pemHeaderRaftDEK:        r.data.CurrentDEK,
		pemHeaderRaftPendingDEK: r.data.PendingDEK,
	} {
		if contents != nil {
			dekStr, err := encodePEMHeaderValue(contents, kek)
			if err != nil {
				return nil, nil, err
			}
			headers[headerKey] = dekStr
		}
	}

	// if we go from unencrypted to encrypted, queue a DEK rotation
	needsRotation := r.data.NeedsRotation
	if r.cachedKEK == nil && kek != nil {
		needsRotation = true
	}

	if r.data.NeedsRotation {
		headers[pemHeaderRaftDEKNeedsRotation] = "true"
	}

	// return a function that updates the dek data on write success
	return headers, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.cachedKEK = kek
		r.data.NeedsRotation = needsRotation
	}, nil
}

// CurrentState returns the current state of the raft DEKs
func (r *RaftDEKPEMHeadersManager) CurrentState() (RaftDEKData, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.data, r.cachedKEK
}

// RaftDEKManager manages the raft DEK keys using TLS headers
type RaftDEKManager struct {
	mu sync.Mutex

	kw ca.KeyWriter
	hm *RaftDEKPEMHeadersManager

	rotationCh chan struct{}
}

// NewRaftDEKManager returns a RaftDEKManager that uses the current key writer
// and header manager
func NewRaftDEKManager(kw ca.KeyWriter, hm *RaftDEKPEMHeadersManager) *RaftDEKManager {
	return &RaftDEKManager{
		kw:         kw,
		hm:         hm,
		rotationCh: make(chan struct{}),
	}
}

// GetPendingKey returns the next pending Key
func (r *RaftDEKManager) GetPendingKey() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, _ := r.hm.CurrentState()
	return data.PendingDEK
}

// GetCurrentKey returns the current key
func (r *RaftDEKManager) GetCurrentKey() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, _ := r.hm.CurrentState()
	return data.CurrentDEK
}

// RotationNotify the channel used to notify subscribers as to whether there
// should be a rotation done
func (r *RaftDEKManager) RotationNotify() chan struct{} {
	return r.rotationCh
}

// MaybeDoRotation will wait for a snapshot to finish, and then update the pending and
// current keys
func (r *RaftDEKManager) MaybeDoRotation(cb func(dek []byte) error) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Do we need to create a new DEK?
	data, currentKEK, _, err := r.maybeUpdatePending()
	if err != nil {
		return false, err
	}

	// no rotation needed - just run the cb
	if data.PendingDEK == nil {
		return false, cb(data.CurrentDEK)
	}

	// try to do the rotation
	if err := cb(data.PendingDEK); err != nil {
		return true, err
	}

	var pending []byte
	if data.NeedsRotation {
		pending = encryption.GenerateSecretKey()
	}
	newHM := NewRaftDEKPEMHeadersManager(RaftDEKData{
		CurrentDEK: data.PendingDEK,
		PendingDEK: pending,
	}, currentKEK)

	if err := r.kw.UpdateHeaders(newHM); err != nil {
		return true, err
	}

	r.hm = newHM
	return true, nil
}

// MaybeUpdateKEK does a KEK rotation if one is required
func (r *RaftDEKManager) MaybeUpdateKEK(newKEK []byte) ([]byte, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, currentKEK := r.hm.CurrentState()
	// re-encrypt first - this will set `NeedsRotation to `true` if we are
	// going from a nil KEK to a non-nil KEK
	if subtle.ConstantTimeCompare(currentKEK, newKEK) == 1 {
		return nil, false, nil
	}
	return currentKEK, true, r.kw.RotateKEK(newKEK)
}

func (r *RaftDEKManager) maybeUpdatePending() (RaftDEKData, []byte, bool, error) {
	// if we can't update the rotation, just return - we need to wait for the next
	data, kek := r.hm.CurrentState()
	if !data.NeedsRotation || data.PendingDEK != nil {
		return data, kek, false, nil
	}

	data = RaftDEKData{
		CurrentDEK: data.CurrentDEK,
		PendingDEK: encryption.GenerateSecretKey(),
	}
	newHM := NewRaftDEKPEMHeadersManager(data, kek)
	if err := r.kw.UpdateHeaders(newHM); err != nil {
		return RaftDEKData{}, nil, true, err
	}

	r.hm = newHM
	return data, kek, true, nil
}

// MaybeUpdatePending sees if we need to update the pending key based on whether
// NeedsRotation is true.
func (r *RaftDEKManager) MaybeUpdatePending() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, _, updated, err := r.maybeUpdatePending()
	if err != nil {
		return false, err
	}
	if updated {
		r.rotationCh <- struct{}{}
	}
	return updated, nil
}

func decodePEMHeaderValue(headerValue string, kek []byte) ([]byte, error) {
	var decrypter encryption.Decrypter = encryption.NoopCrypter
	if kek != nil {
		_, decrypter = encryption.Defaults(kek)
	}
	valueBytes, err := base64.StdEncoding.DecodeString(headerValue)
	if err != nil {
		return nil, err
	}
	return encryption.Decrypt(valueBytes, decrypter)
}

func encodePEMHeaderValue(headerValue []byte, kek []byte) (string, error) {
	var encrypter encryption.Encrypter = encryption.NoopCrypter
	if kek != nil {
		encrypter, _ = encryption.Defaults(kek)
	}
	encrypted, err := encryption.Encrypt(headerValue, encrypter)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}
