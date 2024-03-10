package profilefed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// LoadOrGenerateKeys checks whether the file at path exists. If it does,
// the private and public keys at that path are loaded and returned.
// If not, new keys are generated and saved to the given path.
func LoadOrGenerateKeys(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if _, err := os.Stat(path); err != nil {
		return generateKeys(path)
	}
	return loadKeys(path)
}

func loadKeys(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	privData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	pubData, err := os.ReadFile(path + ".pub")
	if err != nil {
		return nil, nil, err
	}

	privBlock, _ := pem.Decode(privData)
	pubBlock, _ := pem.Decode(pubData)

	if privBlock == nil {
		return nil, nil, errors.New("invalid private key data")
	}

	if pubBlock == nil {
		return nil, nil, errors.New("invalid public key data")
	}

	privkey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	pubkey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	priv, ok := privkey.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, errors.New("invalid private key type")
	}

	pub, ok := pubkey.(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("invalid public key type")
	}

	return pub, priv, nil
}

func generateKeys(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privData, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	privBlock := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: privData,
	}

	err = os.WriteFile(path, pem.EncodeToMemory(privBlock), 0o600)
	if err != nil {
		return nil, nil, err
	}

	pubData, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	pubBlock := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: pubData,
	}

	err = os.WriteFile(path+".pub", pem.EncodeToMemory(pubBlock), 0o644)
	if err != nil {
		return nil, nil, err
	}

	return pub, priv, nil
}

// LoadPrivateKeys loads the private keys at all the provided paths.
//
// Any invalid keys are skipped.
func LoadPrivateKeys(paths ...string) []ed25519.PrivateKey {
	out := make([]ed25519.PrivateKey, len(paths))
	for i, path := range paths {
		privkey, err := LoadPrivateKey(path)
		if err != nil {
			continue
		}
		out[i] = privkey
	}
	return out
}

// LoadPrivateKey loads a private Ed25519 key from the given path.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	privData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	privBlock, _ := pem.Decode(privData)

	if privBlock == nil {
		return nil, errors.New("invalid private key data")
	}

	privkey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, err
	}

	priv, ok := privkey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}

	return priv, nil
}
