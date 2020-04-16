package main

import (
	"fmt"
	"log"
	"os"

	"github.com/thycotic/tss-sdk-go/server"
)

func main() {
	tss, _ := server.New(server.Configuration{
		Credentials: server.UserCredential{
			Username: os.Getenv("TSS_USERNAME"),
			Password: os.Getenv("TSS_PASSWORD"),
		},
		Tenant: os.Getenv("TSS_TENANT"),
	})
	s, err := tss.Secret(1)

	if err != nil {
		log.Fatal("Error calling server.Secret", err)
	}

	if pw, ok := s.Field("password"); ok {
		fmt.Print("the password is", pw)
	}
}
