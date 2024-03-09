package profilefed

import "encoding/json"

// Role represents a user's role on a server
type Role string

// Server roles
const (
	RoleServerHost Role = "server_host"
	RoleAdmin      Role = "admin"
	RoleModerator  Role = "moderator"
	RoleDeveloper  Role = "developer"
	RoleUser       Role = "user"
)

// Descriptor represents a ProfileFed descriptor
type Descriptor struct {
	// ID is an arbitrary ID string for the profile.
	ID string `json:"id"`
	// Namespaces is a list of namespaces used in the profile.
	Namespaces []string `json:"namespaces"`
	// DisplayName is the user's preferred display name.
	DisplayName string `json:"display_name"`
	// Username is the user's username.
	Username string `json:"username"`
	// Bio is the user's bio text.
	Bio string `json:"bio"`
	// Role is the user's role on the server. If not set,
	// [RoleUser] is assumed.
	Role Role `json:"role"`
	// Extra is additional user data defined by namespaces
	Extra []Extra `json:"extra"`
}

// Extra represents additional user data defined by namespaces
type Extra struct {
	// Namespace is the namespace URL used in this object
	Namespace string `json:"namespace"`
	// Type is an arbitrary string that represents the type of
	// data in the Data field.
	Type string `json:"type"`
	// Data is the arbitrary additional user data
	Data json.RawMessage `json:"data"`
}
