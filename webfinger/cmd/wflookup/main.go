package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"

	"queerdevs.org/go-webfinger"
)

func main() {
	server := flag.String("server", "", "The server to query for the WebFinger descriptor (e.g. example.com)")
	flag.Parse()

	if len(os.Args) < 2 {
		log.Fatalln("wflookup requires at least one argument")
	}

	res := os.Args[1]

	var desc *webfinger.Descriptor
	var err error
	if *server != "" {
		desc, err = webfinger.Lookup(res, *server)
	} else if strings.HasPrefix(res, "http") {
		desc, err = webfinger.LookupURL(res)
	} else if strings.HasPrefix(res, "acct:") || strings.Contains(res, "@") {
		desc, err = webfinger.LookupAcct(res)
	}

	if err != nil {
		log.Fatalln("Lookup error:", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	err = enc.Encode(desc)
	if err != nil {
		log.Fatalln("JSON encode error:", err)
	}
}
