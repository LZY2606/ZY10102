package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type LocalStore struct{ root string }

func New(root string) (*LocalStore, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &LocalStore{root: root}, nil
}

func (s *LocalStore) Generate(ref, keyType, curve string, bits int) (crypto.Signer, error) {
	if _, err := os.Stat(s.Path(ref)); err == nil {
		return nil, fmt.Errorf("key reference %q already exists", ref)
	}
	var key crypto.Signer
	var err error
	switch keyType {
	case "RSA":
		if bits == 0 {
			bits = 2048
		}
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return nil, errors.New("RSA bits must be 2048, 3072, or 4096")
		}
		key, err = rsa.GenerateKey(rand.Reader, bits)
	case "EC":
		switch curve {
		case "", "P256":
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "P384":
			key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		default:
			return nil, errors.New("EC curve must be P256 or P384")
		}
	case "Ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, errors.New("key type must be RSA, EC, or Ed25519")
	}
	if err != nil {
		return nil, err
	}
	if err := s.Save(ref, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *LocalStore) Save(ref string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	path := s.Path(ref)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *LocalStore) Load(ref string) (crypto.Signer, error) {
	data, err := os.ReadFile(s.Path(ref))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signer")
	}
	return signer, nil
}

func (s *LocalStore) Delete(ref string) error {
	err := os.Remove(s.Path(ref))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *LocalStore) Path(ref string) string {
	return filepath.Join(s.root, filepath.Clean("/"+ref))
}

func PublicKeyDER(key crypto.PublicKey) ([]byte, error) { return x509.MarshalPKIXPublicKey(key) }

func (s *LocalStore) Rename(oldRef, newRef string) error {
	return os.Rename(s.Path(oldRef), s.Path(newRef))
}
