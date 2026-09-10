package main

import (
	"log"
	"os"

	coreserver "github.com/tyj1987/broker/core/server"
)

func main() {
	socketPath := os.Getenv("BROKER_CORE_SOCKET")
	if socketPath == "" {
		log.Fatal("BROKER_CORE_SOCKET is required")
	}
	if err := coreserver.Run(socketPath); err != nil {
		log.Fatal(err)
	}
}
