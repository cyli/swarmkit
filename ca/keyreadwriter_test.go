package ca_test

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/swarmkit/ca"
	"github.com/stretchr/testify/require"
)

// can read and write tls keys that aren't encrypted, and that are encrypted.  without
// a pem header manager, the headers are all preserved and not overwritten
func TestKeyReadWriter(t *testing.T) {
	cert, key, err := ca.GenerateNewCSR()
	require.NoError(t, err)

	expectedKey := key

	tempdir, err := ioutil.TempDir("", "KeyReadWriter")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	path := ca.NewConfigPaths(filepath.Join(tempdir, "subdir")) // to make sure subdirectories are created

	checkCanReadWithKEK := func(kek []byte) *ca.KeyReadWriter {
		k := ca.NewKeyReadWriter(path.Node, kek, nil)
		readCert, readKey, err := k.Read()
		require.NoError(t, err)
		require.Equal(t, cert, readCert)
		// get the version, because we strip it from the return headers
		require.Equal(t, expectedKey, readKey, "Expected %s, Got %s", string(expectedKey), string(readKey))
		return k
	}

	k := ca.NewKeyReadWriter(path.Node, nil, nil)

	// can't read things that don't exist
	_, _, err = k.Read()
	require.Error(t, err)

	// can write an unencrypted key with no updates
	require.NoError(t, k.Write(cert, expectedKey, nil))

	// can read unencrypted
	k = checkCanReadWithKEK(nil)

	// write a key with headers to the key to make sure they're cleaned
	keyBlock, _ := pem.Decode(expectedKey)
	require.NotNil(t, keyBlock)
	keyBlock.Headers = map[string]string{"hello": "world"}
	expectedKey = pem.EncodeToMemory(keyBlock)
	require.NoError(t, ioutil.WriteFile(path.Node.Key, expectedKey, 0600))

	// if a kek is provided, we can still read unencrypted keys
	k = checkCanReadWithKEK([]byte("original kek"))

	// we can update the kek and write at the same time
	require.NoError(t, k.Write(cert, key, &ca.KEKData{KEK: []byte("new kek!")}))

	// the same kek can still read, and will continue to write with this key if
	// no further kek updates are provided
	_, _, err = k.Read()
	require.NoError(t, err)
	require.NoError(t, k.Write(cert, expectedKey, nil)) // because there's no pem header pemHeaderManager
	// all pem headers are stripped

	expectedKey = key

	// without the right kek, we can't read
	k = ca.NewKeyReadWriter(path.Node, []byte("original kek"), nil)
	_, _, err = k.Read()
	require.Error(t, err)

	// same new key, just for sanity
	k = checkCanReadWithKEK([]byte("new kek!"))

	// we can also change the kek back to nil, which means the key is unencrypted
	require.NoError(t, k.Write(cert, key, &ca.KEKData{KEK: nil}))
	checkCanReadWithKEK(nil)
}

type pemHeaderManager struct {
	setHeaders func(map[string]string, ca.KEKData) error
	newHeaders func(ca.KEKData) (map[string]string, func(), error)
}

func (p pemHeaderManager) SetCurrentHeaders(h map[string]string, k ca.KEKData) error {
	if p.setHeaders != nil {
		return p.setHeaders(h, k)
	}
	return fmt.Errorf("set header error")
}

func (p pemHeaderManager) GetNewHeaders(k ca.KEKData) (map[string]string, func(), error) {
	if p.newHeaders != nil {
		return p.newHeaders(k)
	}
	return nil, nil, fmt.Errorf("update header error")
}

// KeyReaderWriter makes a call to a get headers updater, if write is called,
// and set headers, if read is called
func TestKeyReadWriterWithPemHeaderManager(t *testing.T) {
	cert, key, err := ca.GenerateNewCSR()
	require.NoError(t, err)

	// write a key with headers to the key to make sure it gets overwritten
	keyBlock, _ := pem.Decode(key)
	require.NotNil(t, keyBlock)
	keyBlock.Headers = map[string]string{"hello": "world"}
	key = pem.EncodeToMemory(keyBlock)

	tempdir, err := ioutil.TempDir("", "KeyReadWriter")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	path := ca.NewConfigPaths(filepath.Join(tempdir, "subdir")) // to make sure subdirectories are created

	// if if getting new headers fail, writing a key fails, and the key does not rotate
	var count int

	k := ca.NewKeyReadWriter(path.Node, nil, pemHeaderManager{newHeaders: func(ca.KEKData) (map[string]string, func(), error) {
		if count == 0 {
			count++
			return nil, nil, fmt.Errorf("fail")
		}
		return nil, nil, nil
	}})
	// first write will fail
	require.Error(t, k.Write(cert, key, &ca.KEKData{KEK: []byte("failed kek")}))
	// second write will succeed, using the original kek (nil)
	require.NoError(t, k.Write(cert, key, nil))

	var (
		headers map[string]string
		kek     ca.KEKData
	)

	k = ca.NewKeyReadWriter(path.Node, nil, pemHeaderManager{setHeaders: func(h map[string]string, k ca.KEKData) error {
		headers = h
		kek = k
		return nil
	}})

	_, _, err = k.Read()
	require.NoError(t, err)
	require.Equal(t, ca.KEKData{}, kek)
	require.Equal(t, keyBlock.Headers, headers)

	// writing new headers is called with existing headers, and will write a key that has the headers
	// returned by the header update function
	k = ca.NewKeyReadWriter(path.Node, []byte("oldKek"), pemHeaderManager{newHeaders: func(kek ca.KEKData) (map[string]string, func(), error) {
		require.Equal(t, []byte("newKEK"), kek.KEK)
		return map[string]string{"updated": "headers"}, nil, nil
	}})
	require.NoError(t, k.Write(cert, key, &ca.KEKData{KEK: []byte("newKEK")}))

	// make sure headers were correctly set
	k = ca.NewKeyReadWriter(path.Node, []byte("newKEK"), pemHeaderManager{setHeaders: func(h map[string]string, k ca.KEKData) error {
		headers = h
		kek = k
		return nil
	}})
	_, _, err = k.Read()
	require.NoError(t, err)
	require.Equal(t, []byte("newKEK"), kek.KEK)
	require.Equal(t, map[string]string{"updated": "headers"}, headers)
}

func TestKeyReadWriterRotateKEK(t *testing.T) {
	cert, key, err := ca.GenerateNewCSR()
	require.NoError(t, err)

	tempdir, err := ioutil.TempDir("", "KeyReadWriter")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	path := ca.NewConfigPaths(filepath.Join(tempdir))

	// write a key with headers to the key to make sure it gets passed when reading/writing headers
	keyBlock, _ := pem.Decode(key)
	require.NotNil(t, keyBlock)
	keyBlock.Headers = map[string]string{"hello": "world"}
	key = pem.EncodeToMemory(keyBlock)
	require.NoError(t, ca.NewKeyReadWriter(path.Node, nil, nil).Write(cert, key, nil))

	// if if getting new headers fail, rotating a KEK fails, and the kek does not rotate
	k := ca.NewKeyReadWriter(path.Node, nil, pemHeaderManager{newHeaders: func(ca.KEKData) (map[string]string, func(), error) {
		return nil, nil, fmt.Errorf("fail")
	}})
	require.Error(t, k.RotateKEK(ca.KEKData{KEK: []byte("failed kek"), Version: uint64(3)}))

	// writing new headers will write a key that has the headers returned by the header update function
	k = ca.NewKeyReadWriter(path.Node, []byte("oldKEK"), pemHeaderManager{newHeaders: func(kek ca.KEKData) (map[string]string, func(), error) {
		require.Equal(t, []byte("newKEK"), kek.KEK)
		return map[string]string{"updated": "headers"}, nil, nil
	}})
	require.NoError(t, k.RotateKEK(ca.KEKData{KEK: []byte("newKEK"), Version: uint64(2)}))

	// ensure the key has been re-encrypted and we can read it
	k = ca.NewKeyReadWriter(path.Node, nil, nil)
	_, _, err = k.Read()
	require.Error(t, err)

	var headers map[string]string

	k = ca.NewKeyReadWriter(path.Node, []byte("newKEK"), pemHeaderManager{setHeaders: func(h map[string]string, _ ca.KEKData) error {
		headers = h
		return nil
	}})
	_, _, err = k.Read()
	require.NoError(t, err)
	require.Equal(t, map[string]string{"updated": "headers"}, headers)
}
