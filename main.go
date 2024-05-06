package main

import (
	"fmt"
	"encoding/json"
	"log"
	"os"

	"github.com/DelineaXPM/tss-sdk-go/v2/server"
	
	_"github.com/tidwall/gjson"
)
/*
TSS_USERNAME
TSS_PASSWORD
TSS_TENANT
TSS_SERVER_URL
TSS_TLD
*/

func main() {
	os.Setenv("TSS_USERNAME", "dsvtest")
	os.Setenv("TSS_PASSWORD", "testTEST1234!")
	os.Setenv("TSS_SERVER_URL", "https://rasteamdev.qa.devsecretservercloud.com")



	tss, err := server.New(server.Configuration{
		Credentials: server.UserCredential{
			Username: os.Getenv("TSS_USERNAME"),
			Password: os.Getenv("TSS_PASSWORD"),
		},
/* 		Tenant: os.Getenv("TSS_TENANT"), */
	    ServerURL: os.Getenv("TSS_SERVER_URL"),
	    TLD: "com",
	})

	if err != nil {
		log.Fatal("Error initializing the server configuration", err)
	}

// Get secret by ID
/*	s, err := tss.Secret(49490) // Unix Account (SSH) 					   password = Items.2.ItemValue  */
/*	s, err := tss.Secret(49268) // Unix Account (SSH) 					   password = Items.2.ItemValue */
/*	s, err := tss.Secret(51462) // DevOps Secrets Vault Client Credentials password = Items.2.ItemValue */
/*	s, err := tss.Secret(51463) // MySql Account 						   password = Items.2.ItemValue */
/*	s, err := tss.Secret(51468) // Oracle Account						   password = Items.4.ItemValue */
/*	s, err := tss.Secret(51470) // SQL Server Account					   password = Items.2.ItemValue*/
/*	s, err := tss.Secret(51474) // SAP Account					   		   password = Items.2.ItemValue*/
/*	s, err := tss.Secret(51475) // Windows Account					   	   password = Items.2.ItemValue*/
/*	s, err := tss.Secret(53389) // Unix Account (SSH) 					   password = Items.2.ItemValue  */
	
/*	s, err := tss.Secret(53974) // External-Secret (SSH) 				   data = Items.0.ItemValue  	*/

// Get secret by searchText and field
	s, err := tss.Secrets("ESO-test-secret", "name")
	
// Create new secret
/*
	secretModel := new(server.Secret)
	secretModel.Name = "Bill Test secret delete me"
	secretModel.SiteID = 1
	secretModel.FolderID = 67
	secretModel.SecretTemplateID = 6007
	secretModel.AutoChangeEnabled = false
	secretModel.Fields = make([]server.SecretField, 3)
	secretModel.Fields[0].FieldID = 108 // machine
	secretModel.Fields[0].ItemValue = "DSV TEST MACHINE"
	secretModel.Fields[1].FieldID = 111 // username
	secretModel.Fields[1].ItemValue = "dsv_username"
	secretModel.Fields[2].FieldID = 110 // password
	secretModel.Fields[2].ItemValue = "dsv_password"

	s, err := tss.CreateSecret(*secretModel)
*/

// Update a secret
/*
	secretModel := new(server.Secret)
	secretModel.ID = 49490
	secretModel.Name = "DSV update test secret"
	secretModel.Fields = make([]server.SecretField, 1)
	secretModel.Fields[0].FieldID = 110 // password
	secretModel.Fields[0].ItemValue = "someNewPassword"
	s, err := tss.UpdateSecret(*secretModel)
*/


// Delete Secret
/*
	s := ""
	err = tss.DeleteSecret(53392)
*/

/*
	fmt.Printf("\n\n%+v \n\n", s)
	if err != nil {
		log.Fatal("[Error]: ", err)
	}
*/
	
	jsonStr, err := json.Marshal(s)
	if err != nil {
		fmt.Println(err)
		return
	}
	// extract key from secret using gjson
/*
	val := gjson.Get(string(jsonStr), "Items.0.ItemValue")
	if !val.Exists() {
		fmt.Printf("property = %s ... %s ", val)
		return  
	}
*/

	fmt.Println(string(jsonStr))
	
/*
	if pw, ok := s.Field("password"); ok {
		fmt.Print("\n\nthe password is ", pw, "\n\n")
	}
*/
}
