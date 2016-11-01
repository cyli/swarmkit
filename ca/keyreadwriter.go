package ca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/docker/swarmkit/ioutils"
	"github.com/pkg/errors"
)

const (
	// keyPerms are the permissions used to write the TLS keys
	keyPerms = 0600
	// certPerms are the permissions used to write TLS certificates
	certPerms = 0644
)

// PEMKeyHeaderManager is something that needs to know about PEM headers when reading
// or writing TLS keys.
type PEMKeyHeaderManager interface {
	SetCurrentHeaders(map[string]string, []byte) error
	GetNewHeaders([]byte) (map[string]string, func(), error)
}

// KeyReader reads a TLS cert and key from disk
type KeyReader interface {
	Read() ([]byte, []byte, error)
	Target() string
}

// KeyWriter writes a TLS key and cert to disk
type KeyWriter interface {
	Write([]byte, []byte, *KEKUpdate) error
	UpdateHeaders(PEMKeyHeaderManager) error
	RotateKEK([]byte) error
	Target() string
}

// KEKUpdate provides an optional update to the kek when writing.  The structure
// is needed so that we can tell the difference between "do not encrypt anymore"
// and there is "no update".
type KEKUpdate struct {
	KEK []byte
}

// KeyReadWriter is an object that knows how to read and write TLS keys and certs to disk,
// optionally encrypted and while preserving existing PEM headers.
type KeyReadWriter struct {
	mu            sync.Mutex
	kek           []byte
	paths         CertPaths
	headerManager PEMKeyHeaderManager
}

// NewKeyReadWriter creates a new KeyReadWriter
func NewKeyReadWriter(paths CertPaths, kek []byte, headerManager PEMKeyHeaderManager) *KeyReadWriter {
	return &KeyReadWriter{
		kek:           kek,
		paths:         paths,
		headerManager: headerManager,
	}
}

// Read will read a TLS cert and key from the given paths
func (k *KeyReadWriter) Read() ([]byte, []byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	keyBlock, err := k.readKey()
	if err != nil {
		return nil, nil, err
	}
	if k.headerManager != nil {
		if err := k.headerManager.SetCurrentHeaders(keyBlock.Headers, k.kek); err != nil {
			return nil, nil, errors.Wrap(err, "unable to read TLS key headers")
		}
	}
	cert, err := ioutil.ReadFile(k.paths.Cert)
	if err != nil {
		return nil, nil, err
	}
	return cert, pem.EncodeToMemory(keyBlock), err
}

// RotateKEK re-encrypts the key with a new KEK
func (k *KeyReadWriter) RotateKEK(newKEK []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	keyBlock, err := k.readKey()
	if err != nil {
		return err
	}

	if err := k.writeKey(keyBlock, newKEK, k.headerManager); err != nil {
		return err
	}

	k.kek = newKEK
	return nil
}

// UpdateHeaders updates the header manager, and updates any headers on the existing key
func (k *KeyReadWriter) UpdateHeaders(hm PEMKeyHeaderManager) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	keyBlock, err := k.readKeyblock()
	if err != nil {
		return err
	}

	var onSuccess func()
	if hm != nil {
		headers, successFunc, err := hm.GetNewHeaders(k.kek)
		if err != nil {
			return err
		}
		// we WANT any encryption headers
		for key, value := range keyBlock.Headers {
			normalizedKey := strings.TrimSpace(strings.ToLower(key))
			if normalizedKey == "proc-type" || normalizedKey == "dek-info" {
				headers[key] = value
			}
		}
		onSuccess = successFunc
		keyBlock.Headers = headers
	}

	if err = ioutils.AtomicWriteFile(k.paths.Key, pem.EncodeToMemory(keyBlock), keyPerms); err != nil {
		return err
	}
	k.headerManager = hm
	if onSuccess != nil {
		onSuccess()
	}
	return nil
}

// Write attempts write a cert and key to text.  This can also optionally update
// the KEK while writing, if an updated KEK is provided.  If the pointer to the
// update KEK is nil, then we don't update. If the updated KEK itself is nil,
// then we update the KEK to be nil (data should be unencrypted).
func (k *KeyReadWriter) Write(certBytes, plaintextKeyBytes []byte, kekUpdate *KEKUpdate) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// current assumption is that the cert and key will be in the same directory
	err := os.MkdirAll(filepath.Dir(k.paths.Key), 0755)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(plaintextKeyBytes)
	if keyBlock == nil {
		return errors.New("invalid PEM-encoded private key")
	}

	useKEK := k.kek
	if kekUpdate != nil {
		useKEK = kekUpdate.KEK
	}
	if err := k.writeKey(keyBlock, useKEK, k.headerManager); err != nil {
		return err
	}

	k.kek = useKEK
	return ioutils.AtomicWriteFile(k.paths.Cert, certBytes, certPerms)
}

// Target returns a string representation of this KeyReadWriter, namely where
// it is writing to
func (k *KeyReadWriter) Target() string {
	return k.paths.Cert
}

func (k *KeyReadWriter) readKeyblock() (*pem.Block, error) {
	key, err := ioutil.ReadFile(k.paths.Key)
	if err != nil {
		return nil, err
	}

	// Decode the PEM private key
	keyBlock, _ := pem.Decode(key)
	if keyBlock == nil {
		return nil, errors.New("invalid PEM-encoded private key")
	}

	return keyBlock, nil
}

// readKey returns the decrypted key pem bytes, and enforces the KEK if applicable
// (writes it back with the correct encryption if it is not correctly encrypted)
func (k *KeyReadWriter) readKey() (*pem.Block, error) {
	keyBlock, err := k.readKeyblock()
	if err != nil {
		return nil, err
	}

	if !x509.IsEncryptedPEMBlock(keyBlock) {
		return keyBlock, nil
	}

	derBytes, err := x509.DecryptPEMBlock(keyBlock, k.kek)
	if err != nil {
		return nil, err
	}
	// remove encryption PEM headers
	headers := make(map[string]string)
	mergePEMHeaders(headers, keyBlock.Headers)

	return &pem.Block{
		Type:    keyBlock.Type, // the key type doesn't change
		Bytes:   derBytes,
		Headers: headers,
	}, nil
}

// writeKey takes an unencrypted keyblock and, if the kek is not nil, encrypts it before
// writing it to disk.  If the kek is nil, writes it to disk unencrypted.
func (k *KeyReadWriter) writeKey(keyBlock *pem.Block, writeKEK []byte, hm PEMKeyHeaderManager) error {
	if writeKEK != nil {
		encryptedPEMBlock, err := x509.EncryptPEMBlock(rand.Reader,
			keyBlock.Type,
			keyBlock.Bytes,
			writeKEK,
			x509.PEMCipherAES256)
		if err != nil {
			return err
		}
		if encryptedPEMBlock.Headers == nil {
			return errors.New("unable to encrypt key - invalid PEM file produced")
		}
		keyBlock = encryptedPEMBlock
	}

	var onSuccess func()
	if hm != nil {
		headers, successFunc, err := hm.GetNewHeaders(writeKEK)
		if err != nil {
			return err
		}
		mergePEMHeaders(keyBlock.Headers, headers)
		onSuccess = successFunc
	}

	if err := ioutils.AtomicWriteFile(k.paths.Key, pem.EncodeToMemory(keyBlock), keyPerms); err != nil {
		return err
	}
	if onSuccess != nil {
		onSuccess()
	}
	return nil
}

// merges one set of PEM headers onto another, excepting for key encryption value
// "proc-type" and "dek-info"
func mergePEMHeaders(original, newSet map[string]string) {
	for key, value := range newSet {
		normalizedKey := strings.TrimSpace(strings.ToLower(key))
		if normalizedKey != "proc-type" && normalizedKey != "dek-info" {
			original[key] = value
		}
	}
}
