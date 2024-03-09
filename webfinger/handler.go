package webfinger

import (
	"encoding/json"
	"net/http"
)

// Handler handles WebFinger requests to an HTTP server
type Handler struct {
	// DescriptorFunc is the function used to resolve resource strings
	// to WebFinger descriptors. It's called on every request to the
	// WebFinger endpoint. The errors it returns are handled by ErrorHandler.
	DescriptorFunc func(resource string) (*Descriptor, error)

	// ErrorHandler handles any errors that occur in the process of performing
	// a WebFinger lookup. If not provided, a simple default handler is used.
	ErrorHandler func(err error, res http.ResponseWriter)
}

// ServeHTTP implements the http.Handler interface
func (h Handler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if h.ErrorHandler == nil {
		h.ErrorHandler = func(err error, res http.ResponseWriter) {
			http.Error(res, err.Error(), http.StatusInternalServerError)
		}
	}

	descriptor, err := h.DescriptorFunc(req.URL.Query().Get("resource"))
	if err != nil {
		h.ErrorHandler(err, res)
		return
	}

	data, err := json.Marshal(descriptor)
	if err != nil {
		h.ErrorHandler(err, res)
		return
	}

	res.Header().Set("Content-Type", "application/jrd+json")
	_, err = res.Write(data)
	if err != nil {
		h.ErrorHandler(err, res)
		return
	}
}
