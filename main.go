package main

import (
	"fmt"
	"log"
	"os"

	"github.com/DelineaXPM/tss-sdk-go/v2/server"
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

	if pw, ok := s.Field("password"); ok {
		fmt.Print("the password is", pw)
	}
}
