package server_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/DelineaXPM/tss-sdk-go/v3/server"
)

func ExampleServer_SecretContext() {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":42,"name":"database credential","fields":[{"fieldName":"Password","slug":"password","itemValue":"not-printed","isPassword":true}]}`)
	}))
	defer api.Close()

	tss, err := server.New(server.Configuration{
		ServerURL:   api.URL,
		Credentials: server.UserCredential{Token: "caller-supplied-token"},
	})
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	secret, err := tss.SecretContext(ctx, 42)
	if err != nil {
		panic(err)
	}
	fmt.Printf("retrieved secret %d (%s)\n", secret.ID, secret.Name)
	// Output: retrieved secret 42 (database credential)
}
