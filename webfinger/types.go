package webfinger

// Descriptor represents a WebFinger JSON Resource Descriptor (JRD)
type Descriptor struct {
	Subject    string            `json:"subject"`
	Aliases    []string          `json:"aliases"`
	Properties map[string]string `json:"properties,omitempty"`
	Links      []Link            `json:"links"`
}

// Link represents a JRD link item
type Link struct {
	Rel  string `json:"rel"`
	Type string `json:"type,omitempty"`
	Href string `json:"href"`
}

// LinkByType searches for a link with the given type. If found, it returns
// the link and true. Otherwise, it returns the zero value and false.
func (d *Descriptor) LinkByType(linkType string) (Link, bool) {
	for _, link := range d.Links {
		if link.Type == linkType {
			return link, true
		}
	}
	return Link{}, false
}

// LinkByRel searches for a link with the given rel value. If found, it returns
// the link and true. Otherwise, it returns the zero value and false.
func (d *Descriptor) LinkByRel(rel string) (Link, bool) {
	for _, link := range d.Links {
		if link.Rel == rel {
			return link, true
		}
	}
	return Link{}, false
}
