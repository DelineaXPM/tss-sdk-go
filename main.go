package main

import (
	"fmt"
	"github.com/thycotic/tss-sdk-go/server"
	"log"
	"os"
)

func main() {
	tss := server.New(server.Configuration{
		Username: os.Getenv("TSS_API_USERNAME"),
		Password: os.Getenv("TSS_API_PASSWORD"),
		Tenant:   os.Getenv("TSS_API_TENANT"),
	})
	s, err := tss.Secret(1)

	if err != nil {
		log.Fatal("Error calling server.Secret", err)
	}

	if pw, ok := s.Field("password"); ok {
		fmt.Print("the password is", pw)
	}
}
