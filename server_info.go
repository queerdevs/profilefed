package profilefed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// ServerInfoHandler handles the server info endpoint
// defined by ProfileFed.
type ServerInfoHandler struct {
	// ServerName is the current name of the server. This
	// should be the same as the domain used to access it.
	ServerName string
	// PreviousNames should contain any previous names this server used.
	PreviousNames []string

	// PublicKey should contain the server's public Ed25519 key.
	PublicKey ed25519.PublicKey
	// PrivateKey should contain the server's private Ed25519 key.
	PrivateKey ed25519.PrivateKey
	// PreviousKeys should contain any previously-used private keys.
	// If this is not provided when the key changes, servers will not
	// trust the new key and all responses will be rejected.
	PreviousKeys []ed25519.PrivateKey

	// ErrorHandler is called whenever an error is encountered.
	ErrorHandler func(err error, res http.ResponseWriter)
}

type serverInfoData struct {
	ServerName    string   `json:"server_name"`
	PreviousNames []string `json:"previous_names"`
	PublicKey     string   `json:"pubkey"`
}

// ServeHTTP implements the http.Handler interface
func (sih ServerInfoHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	data, err := json.Marshal(serverInfoData{
		ServerName:    sih.ServerName,
		PreviousNames: sih.PreviousNames,
		PublicKey:     base64.StdEncoding.EncodeToString(sih.PublicKey),
	})
	if err != nil {
		sih.ErrorHandler(err, res)
		return
	}

	for _, key := range sih.PreviousKeys {
		sig := ed25519.Sign(key, data)
		res.Header().Add("X-ProfileFed-Previous", base64.StdEncoding.EncodeToString(sig))
	}

	sig := ed25519.Sign(sih.PrivateKey, data)
	res.Header().Set("X-ProfileFed-Sig", base64.StdEncoding.EncodeToString(sig))

	_, err = res.Write(data)
	if err != nil {
		sih.ErrorHandler(err, res)
		return
	}
}
