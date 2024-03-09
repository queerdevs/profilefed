package webfinger

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Lookup looks up the given resource string at the given server.
// The server parameter shouldn't contain a URL scheme.
func Lookup(resource, server string) (desc *Descriptor, err error) {
	u := url.URL{
		Scheme:   "http",
		Host:     server,
		Path:     "/.well-known/webfinger",
		RawQuery: "resource=" + url.QueryEscape(resource),
	}

	res, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New(res.Status)
	}

	desc = &Descriptor{}
	err = json.NewDecoder(res.Body).Decode(desc)
	if err != nil {
		return nil, err
	}

	return desc, nil
}

// LookupAcct looks up the given account ID. It uses the
// server in the ID to do the lookup. For example, user@example.com
// would use example.com as the server.
func LookupAcct(id string) (*Descriptor, error) {
	_, server, ok := strings.Cut(id, "@")
	if !ok {
		return nil, errors.New("invalid acct id")
	}
	if !strings.HasPrefix(id, "acct:") {
		id = "acct:" + id
	}
	return Lookup(id, server)
}

// LookupURL looks up the given resource URL. It uses the
// URL host to do the lookup. For example, http://example.com/1
// would use example.com as the server.
func LookupURL(resource string) (*Descriptor, error) {
	u, err := url.ParseRequestURI(resource)
	if err != nil {
		return nil, err
	}
	return Lookup(resource, u.Host)
}
