package profilefed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
)

// ErrDescriptorNotFound should be returned
var ErrDescriptorNotFound = errors.New("descriptor not found")

// AddExtra is a convenience function that adds an extra data object to the descriptor.
// It defines any undefined namespaces and marshals the data parameter into JSON.
func (d *Descriptor) AddExtra(namespace, etype string, data any) error {
	// Remove the fragment from the namespace URL if it exists
	urlStr, _, _ := strings.Cut(namespace, "#")

	if !slices.Contains(d.Namespaces, urlStr) {
		d.Namespaces = append(d.Namespaces, urlStr)
	}

	msg, err := json.Marshal(data)
	if err != nil {
		return err
	}

	d.Extra = append(d.Extra, Extra{
		Namespace: namespace,
		Type:      etype,
		Data:      msg,
	})

	return nil
}

type Handler struct {
	// PrivateKey contains the server's Ed25519 private key for signing responses
	PrivateKey ed25519.PrivateKey

	// AllDescriptorsFunc should return all the profile descriptors known to the server.
	// If no matching descriptors can be found, AllDescriptorsFunc should reutnr
	// [ErrDescriptorNotFound].
	AllDescriptorsFunc func(req *http.Request) (map[string]*Descriptor, error)

	// DescriptorFunc should return a single descriptor. Make sure to check the `id`
	// query parameter if your user has several descriptors available. If a matching
	// descriptor cannot be found, DescriptorFunc should return [ErrDescriptorNotFound].
	DescriptorFunc func(req *http.Request) (*Descriptor, error)

	// ErrorHandler is called whenever an error is encountered.
	ErrorHandler func(err error, res http.ResponseWriter)
}

// ServeHTTP implements the [http.Handler] interface
func (h Handler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	var data []byte
	if req.URL.Query().Get("all") == "1" {
		descriptors, err := h.AllDescriptorsFunc(req)
		if err != nil {
			h.ErrorHandler(err, res)
			return
		}

		data, err = json.Marshal(descriptors)
		if err != nil {
			h.ErrorHandler(err, res)
			return
		}
	} else {
		descriptor, err := h.DescriptorFunc(req)
		if err != nil {
			h.ErrorHandler(err, res)
			return
		}

		data, err = json.Marshal(descriptor)
		if err != nil {
			h.ErrorHandler(err, res)
			return
		}
	}

	sig := ed25519.Sign(h.PrivateKey, data)
	res.Header().Set("X-ProfileFed-Sig", base64.StdEncoding.EncodeToString(sig))
	res.Header().Set("Content-Type", "application/x-pfd+json")

	_, err := res.Write(data)
	if err != nil {
		h.ErrorHandler(err, res)
		return
	}
}
