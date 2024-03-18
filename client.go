package profilefed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"queerdevs.org/profilefed/webfinger"
)

const responseSizeLimit = 32_000_000

var (
	// ErrPubkeyNotFound signifies that the server public key is not found.
	ErrPubkeyNotFound = errors.New("server pubkey not found")
	// ErrNoSignature signifies that the response contains no signature.
	ErrNoSignature = errors.New("response contains no signature")
	// ErrSignatureMismatch signifies that the message does not match the server signature.
	ErrSignatureMismatch = errors.New("message does not match server signature")
)

// DefaultClient returns a default client for ProfileFed.
//
// It uses an in-memory synchronized map to store public keys.
// For production, it's highly recommended to implement a custom
// client that persists the keys to a database or similar, so that
// restarting your app doesn't provide opportunities for malicious servers.
func DefaultClient() Client {
	defaultMap := sync.Map{}
	return Client{
		SavePubkey: func(serverName string, previousNames []string, pubkey ed25519.PublicKey) error {
			defaultMap.Store(serverName, pubkey)
			for _, name := range previousNames {
				defaultMap.Delete(name)
			}
			return nil
		},
		GetPubkey: func(serverName string) (ed25519.PublicKey, error) {
			pubkey, ok := defaultMap.Load(serverName)
			if !ok {
				return nil, ErrPubkeyNotFound
			}
			return pubkey.(ed25519.PublicKey), nil
		},
	}
}

// Client represents a ProfileFed client
type Client struct {
	// SavePubkey saves the public key for a given server.
	SavePubkey func(serverName string, previousNames []string, pubkey ed25519.PublicKey) error

	// GetPubkey retrieves the public key for a given server.
	// If the key isn't found, GetPubkey should return [ErrPubkeyNotFound]
	GetPubkey func(serverName string) (ed25519.PublicKey, error)
}

// Lookup looks up the profile descriptor for the given resource.
func (c Client) Lookup(resource string) (*Descriptor, error) {
	wfdesc, err := webfinger.LookupAcct(resource)
	if err != nil {
		return nil, err
	}

	out := &Descriptor{}
	return out, c.lookup(wfdesc, "", false, out)
}

// LookupID looks up the profile descriptor that matches the given ID
// for the given resource.
func (c Client) LookupID(resource, id string) (*Descriptor, error) {
	wfdesc, err := webfinger.LookupAcct(resource)
	if err != nil {
		return nil, err
	}

	out := &Descriptor{}
	return out, c.lookup(wfdesc, id, false, out)
}

// Lookup looks up all the available profile descriptors for the given resource.
func (c Client) LookupAll(resource string) (map[string]*Descriptor, error) {
	wfdesc, err := webfinger.LookupAcct(resource)
	if err != nil {
		return nil, err
	}

	out := map[string]*Descriptor{}
	return out, c.lookup(wfdesc, "", true, &out)
}

// LookupWebFinger is the same as [Client.Lookup], but it accepts an existing WebFinger
// descriptor rather than looking one up.
func (c Client) LookupWebFinger(wfdesc *webfinger.Descriptor) (*Descriptor, error) {
	out := &Descriptor{}
	return out, c.lookup(wfdesc, "", false, out)
}

// LookupWebFingerID is the same as [Client.LookupID], but it accepts an existing WebFinger
// descriptor rather than looking one up.
func (c Client) LookupWebFingerID(wfdesc *webfinger.Descriptor, id string) (*Descriptor, error) {
	out := &Descriptor{}
	return out, c.lookup(wfdesc, id, false, out)
}

// LookupAllWebFinger is the same as [Client.LookupAll], but it accepts an existing WebFinger
// descriptor rather than looking one up.
func (c Client) LookupAllWebFinger(wfdesc *webfinger.Descriptor) (map[string]*Descriptor, error) {
	out := map[string]*Descriptor{}
	return out, c.lookup(wfdesc, "", true, out)
}

func (c Client) lookup(wfdesc *webfinger.Descriptor, id string, all bool, dest any) error {
	pfdLink, ok := wfdesc.LinkByType("application/x-pfd+json")
	if !ok {
		return errors.New("server does not support the profilefed protocol")
	}

	pfdURL, err := url.Parse(pfdLink.Href)
	if err != nil {
		return err
	}

	pubkeySaved := false
	pubkey, err := c.GetPubkey(pfdURL.Host)
	if errors.Is(err, ErrPubkeyNotFound) {
		data, sig, prevSigs, err := getServerInfo(pfdURL.Scheme, pfdURL.Host)
		if err != nil {
			return err
		}

		var info serverInfoData
		err = json.Unmarshal(data, &info)
		if err != nil {
			return err
		}

		// If this server is advertising previous names, make sure
		// we verify that it's telling the truth by checking the whether
		// any of its signatures match using the pubkeys of the previous names.
		if len(info.PreviousNames) > 0 {
			for _, prevName := range info.PreviousNames {
				pubkey, err = c.GetPubkey(prevName)
				if errors.Is(err, ErrPubkeyNotFound) {
					continue
				} else if err != nil {
					return err
				}

				if ed25519.Verify(pubkey, data, sig) {
					break
				}

				for _, prevSig := range prevSigs {
					if ed25519.Verify(pubkey, data, prevSig) {
						break
					}
				}

				// If we haven't broken out of the loop by now, this
				// name could not be verified, so return an error.
				return ErrSignatureMismatch
			}
		}

		pubkey, err = base64.StdEncoding.DecodeString(info.PublicKey)
		if err != nil {
			return err
		}

		err = c.SavePubkey(pfdURL.Host, info.PreviousNames, pubkey)
		if err != nil {
			return err
		}
		pubkeySaved = true
	} else if err != nil {
		return err
	}

	q := pfdURL.Query()
	if all {
		q.Set("all", "1")
	} else if id != "" {
		q.Set("id", id)
	}
	pfdURL.RawQuery = q.Encode()

	res, err := http.Get(pfdURL.String())
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if err := checkResp(res, "getProfileDescriptor"); err != nil {
		return err
	}

	data, err := io.ReadAll(io.LimitReader(res.Body, responseSizeLimit))
	if err != nil {
		return err
	}

	if err := res.Body.Close(); err != nil {
		return err
	}

	sig, err := getSignature(res)
	if err != nil {
		return err
	}

	if !ed25519.Verify(pubkey, data, sig) {
		// If the pubkey was just saved in the current request, we probably
		// already have the newest one, so just return a mismatch error.
		if pubkeySaved {
			return ErrSignatureMismatch
		}

		serverData, infoSig, sigs, err := getServerInfo(pfdURL.Scheme, pfdURL.Host)
		if err != nil {
			return err
		}

		var info serverInfoData
		err = json.Unmarshal(serverData, &info)
		if err != nil {
			return err
		}

		newPubkey, err := base64.StdEncoding.DecodeString(info.PublicKey)
		if err != nil {
			return err
		}

		// If the pubkey hasn't changed but we couldn't
		// verify the signature, return an error immediately.
		if bytes.Equal(pubkey, newPubkey) {
			return ErrSignatureMismatch
		}

		verified := false
		for _, sig := range sigs {
			if ed25519.Verify(pubkey, serverData, sig) {
				verified = true
				break
			}
		}

		if !verified {
			return ErrSignatureMismatch
		}

		if !ed25519.Verify(newPubkey, infoSig, serverData) {
			return ErrSignatureMismatch
		}

		err = c.SavePubkey(pfdURL.Host, info.PreviousNames, newPubkey)
		if err != nil {
			return err
		}

		if !ed25519.Verify(newPubkey, data, sig) {
			return ErrSignatureMismatch
		}
	}

	return json.Unmarshal(data, dest)
}

// getServerInfo retrieves server information.
func getServerInfo(scheme, host string) (data, sig []byte, prevSigs [][]byte, err error) {
	serverInfoURL := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   "/_profilefed/server",
	}

	res, err := http.Get(serverInfoURL.String())
	if err != nil {
		return nil, nil, nil, err
	}
	defer res.Body.Close()

	if err := checkResp(res, "getServerInfo"); err != nil {
		return nil, nil, nil, err
	}

	sig, err = getSignature(res)
	if err != nil {
		return nil, nil, nil, err
	}

	data, err = io.ReadAll(io.LimitReader(res.Body, responseSizeLimit))
	return data, sig, getPrevSignatures(res), err
}

// getPrevSignatures extracts previous signatures from a response.
func getPrevSignatures(res *http.Response) [][]byte {
	var sigs [][]byte
	sigStrs := res.Header[http.CanonicalHeaderKey("X-ProfileFed-Previous")]
	for _, sigStr := range sigStrs {
		sig, err := base64.StdEncoding.DecodeString(sigStr)
		if err != nil {
			continue // Skip invalid signatures
		}
		sigs = append(sigs, sig)
	}
	return sigs
}

// getSignature extracts the signature from a response.
func getSignature(res *http.Response) ([]byte, error) {
	sigStr := res.Header.Get("X-ProfileFed-Sig")
	if sigStr == "" {
		return nil, ErrNoSignature
	}
	return base64.StdEncoding.DecodeString(sigStr)
}

// checkResp returns an error if the response is not 200 OK.
func checkResp(res *http.Response, opName string) error {
	if res.StatusCode != 200 {
		return fmt.Errorf("%s: %s", opName, res.Status)
	}
	return nil
}
