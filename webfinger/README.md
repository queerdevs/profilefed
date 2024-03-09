# WebFinger

This is a simple implementation of a Go server handler and client for the WebFinger discovery protocol ([RFC7033](https://datatracker.ietf.org/doc/html/rfc7033)).

## `wflookup`

This package includes a command that looks up WebFinger descriptors. You can install it with the following command:

```bash
go install queerdevs.org/profilefed/webfinger/cmd/wflookup@latest
```

Here are some examples for how to use it:

```bash
wflookup acct:user@example.com
wflookup http://example.com/resource/1
wflookup user@example.com # wflookup will infer the acct scheme
```

If you'd like to specify the server that's going to be used instead of it being inferred, you can do so using the `--server` flag.

## Example library usage

### Server

```go
package main

import (
	"net/http"

	"queerdevs.org/profilefed/webfinger"
)

func main() {
	mux := http.NewServeMux()

	mux.Handle("GET /.well-known/webfinger", Handler{
		DescriptorFunc: func(resource string) (*Descriptor, error) {
			// You can query a database here, or do whatever you need
			// to in order to get the descriptor data.
			return desc, nil
		},
	})

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		panic(err)
	}
}
```

### Client

```go
package main

import (
	"fmt"

	"queerdevs.org/profilefed/webfinger"
)

func main() {
	desc, err := webfinger.Lookup("acct:user@example.com", "example.com:8080")
	if err != nil {
		panic(err)
	}
	fmt.Println(desc)

	desc, err = webfinger.LookupAcct("user@example.com")
	if err != nil {
		panic(err)
	}
	fmt.Println(desc)

	desc, err = webfinger.LookupURL("http://example.com/resource/1")
	if err != nil {
		panic(err)
	}
	fmt.Println(desc)
}
