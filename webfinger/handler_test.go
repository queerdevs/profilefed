package webfinger

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestHandler(t *testing.T) {
	testdata := map[string]*Descriptor{
		"acct:user@example.com": {
			Subject: "acct:user@example.com",
			Aliases: []string{
				"mailto:user@example.com",
				"https://www.example.com/user",
			},
			Links: []Link{
				{
					Rel:  "http://webfinger.net/rel/profile-page",
					Type: "text/html",
					Href: "https://www.example.com/user",
				},
			},
		},
		"http://example.com/resource/1": {
			Subject: "http://example.com/resource/1",
			Properties: map[string]string{
				"http://example.com/ns/example#publish-date": "2023-04-26",
			},
		},
	}

	srv := httptest.NewServer(Handler{
		DescriptorFunc: func(resource string) (*Descriptor, error) {
			// Look for the descriptor in the testdata map
			desc, ok := testdata[resource]
			if !ok {
				return nil, errors.New("descriptor not found")
			}
			return desc, nil
		},
		ErrorHandler: func(err error, res http.ResponseWriter) {
			http.Error(res, err.Error(), http.StatusInternalServerError)
		},
	})
	defer srv.Close()

	// Look up acct resource
	desc, err := Lookup("acct:user@example.com", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Lookup error: %s", err)
	}

	if !reflect.DeepEqual(desc, testdata["acct:user@example.com"]) {
		t.Errorf("Descriptors are not equal:\n%#v\n\n%#v", desc, testdata["acct:user@example.com"])
	}

	// Look up URL resource
	desc, err = Lookup("http://example.com/resource/1", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Lookup error: %s", err)
	}

	if !reflect.DeepEqual(desc, testdata["http://example.com/resource/1"]) {
		t.Errorf("Descriptors are not equal:\n%#v\n\n%#v", desc, testdata["http://example.com/resource/1"])
	}

	// Look up a non-existent resource to test error handling
	desc, err = Lookup("http://example.com/resource/2", srv.Listener.Addr().String())
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}
