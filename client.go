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

// Lookup looks up the profile descriptor for the given ID.
func (c Client) Lookup(id string) (*Descriptor, error) {
	wfdesc, err := webfinger.LookupAcct(id)
	if err != nil {
		return nil, err
	}

	pfdLink, ok := wfdesc.LinkByType("application/x-pfd+json")
	if !ok {
		return nil, errors.New("server does not support the profilefed protocol")
	}

	pfdURL, err := url.Parse(pfdLink.Href)
	if err != nil {
		return nil, err
	}

	pubkeySaved := false
	pubkey, err := c.GetPubkey(pfdURL.Host)
	if errors.Is(err, ErrPubkeyNotFound) {
		info, _, err := getServerInfo(pfdURL.Scheme, pfdURL.Host)
		if err != nil {
			return nil, err
		}

		pubkey, err = base64.StdEncoding.DecodeString(info.PublicKey)
		if err != nil {
			return nil, err
		}

		err = c.SavePubkey(pfdURL.Host, info.PreviousNames, pubkey)
		if err != nil {
			return nil, err
		}
		pubkeySaved = true
	} else if err != nil {
		return nil, err
	}

	res, err := http.Get(pfdLink.Href)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if err := checkResp(res, "getProfileDescriptor"); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(io.LimitReader(res.Body, responseSizeLimit))
	if err != nil {
		return nil, err
	}

	if err := res.Body.Close(); err != nil {
		return nil, err
	}

	sig, err := getSignature(res)
	if err != nil {
		return nil, err
	}

	if !ed25519.Verify(pubkey, data, sig) {
		// If the pubkey was just saved in the current request, we probably
		// already have the newest one, so just return a mismatch error.
		if pubkeySaved {
			return nil, ErrSignatureMismatch
		}

		res, err := serverInfoReq(pfdURL.Scheme, pfdURL.Host)
		if err != nil {
			return nil, err
		}

		serverData, err := io.ReadAll(io.LimitReader(res.Body, responseSizeLimit))
		if err != nil {
			return nil, err
		}

		var info serverInfoData
		err = json.Unmarshal(serverData, &info)
		if err != nil {
			return nil, err
		}

		newPubkey, err := base64.StdEncoding.DecodeString(info.PublicKey)
		if err != nil {
			return nil, err
		}

		if bytes.Equal(pubkey, newPubkey) {
			return nil, ErrSignatureMismatch
		}

		verified := false
		sigs := getPrevSignatures(res)
		for _, sig := range sigs {
			if ed25519.Verify(pubkey, serverData, sig) {
				verified = true
				break
			}
		}

		if !verified {
			return nil, ErrSignatureMismatch
		}

		infoSig, err := getSignature(res)
		if err != nil {
			return nil, err
		}

		if !ed25519.Verify(newPubkey, infoSig, serverData) {
			return nil, ErrSignatureMismatch
		}

		err = c.SavePubkey(pfdURL.Host, info.PreviousNames, newPubkey)
		if err != nil {
			return nil, err
		}

		if !ed25519.Verify(newPubkey, data, sig) {
			return nil, ErrSignatureMismatch
		}
	}

	desc := &Descriptor{}
	err = json.Unmarshal(data, desc)
	if err != nil {
		return nil, err
	}

	if desc.Role == "" {
		desc.Role = RoleUser
	}

	return desc, nil
}

// serverInfoReq performs an HTTP request to retrieve server information.
func serverInfoReq(scheme, host string) (*http.Response, error) {
	serverInfoURL := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   "/_profilefed/server",
	}
	return http.Get(serverInfoURL.String())
}

// getServerInfo retrieves server information.
func getServerInfo(scheme, host string) (serverInfoData, [][]byte, error) {
	res, err := serverInfoReq(scheme, host)
	if err != nil {
		return serverInfoData{}, nil, err
	}
	defer res.Body.Close()

	if err := checkResp(res, "getServerInfo"); err != nil {
		return serverInfoData{}, nil, err
	}

	var out serverInfoData
	err = json.NewDecoder(io.LimitReader(res.Body, responseSizeLimit)).Decode(&out)
	return out, getPrevSignatures(res), err
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
