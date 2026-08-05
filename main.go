package main

import (
	"log"
	"os"

	"github.com/DelineaXPM/tss-sdk-go/v3/server"
)

func main() {
	tss, err := server.New(server.Configuration{
		Credentials: server.UserCredential{
			Username: os.Getenv("TSS_USERNAME"),
			Password: os.Getenv("TSS_PASSWORD"),
		},
		Tenant: os.Getenv("TSS_TENANT"),
	})

	if err != nil {
		log.Fatal("Error initializing the server configuration", err)
	}

	s, err := tss.Secret(1)

	if err != nil {
		log.Fatal("Error calling server.Secret", err)
	}

	if _, ok := s.Field("password"); !ok {
		log.Fatal("The secret has no password field")
	}
	log.Printf("Retrieved secret %d (%s)", s.ID, s.Name)
}
