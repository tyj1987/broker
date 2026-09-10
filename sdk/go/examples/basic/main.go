// Package main is a minimal example of the broker Go SDK.
//
// Build: cd sdk/go && go run ./examples/basic
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/tyj1987/broker/sdk/go/broker"
)

func main() {
	c, err := broker.NewClient(broker.Config{
		Endpoint:   "https://broker.example.com:8443",
		ClientCert: "client.crt",
		ClientKey:  "client.key",
		CACert:     "ca.crt",
		Timeout:    10 * time.Second,
	})
	if err != nil {
		log.Fatalf("new client: %v", err)
	}
	ctx := context.Background()

	h, err := c.Health(ctx)
	if err != nil {
		log.Fatalf("health: %v", err)
	}
	fmt.Printf("broker ok=%v version=%s\n", h.OK, h.Version)

	me, err := c.Me(ctx)
	if err != nil {
		log.Fatalf("me: %v", err)
	}
	fmt.Printf("client cn=%s role=%s\n", me.CN, me.Role)

	tok, err := c.GetSecret(ctx, "github.pat")
	if err != nil {
		log.Fatalf("get: %v", err)
	}
	fmt.Printf("github.pat length: %d (value redacted)\n", len(tok))
}
