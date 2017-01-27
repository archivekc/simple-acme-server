package register

import (
	"acme"
	"encoding/json"
	"fmt"
	"jws"
	"model"
	"net/http"
)

// ACME 6.3. Registration

type newRegInput struct {
	Resource string   `json:"resource"`
	Contact  []string `json:"contact"`
}

type newRegOutput struct {
	Jwk     model.JWK `json:"key"`
	Contact []string  `json:"contact"`
}

// HandleNewRegistration handle a new reg request
func HandleNewRegistration(server *model.AcmeServer, w http.ResponseWriter, r *http.Request) {
	content := acme.DebugRequest(r)

	// Check JWS
	client := server.Clients[acme.GetIP(r)]
	payload, protected := jws.ValidateJws(client, w, content)
	var input newRegInput
	err := json.Unmarshal(payload, &input)
	if err != nil {
		panic(err)
	}
	client.Contact = input.Contact
	client.Key = protected.JWK
	client.URI = "https://" + server.Hostname + ":" + server.Port + "/reg/asdf"

	w.Header().Set("Location", client.URI) // FIXME create real client registered url
	w.Header().Set("Link", "<https://"+server.Hostname+":"+server.Port+"/new-authz>;rel=\"next\"")
	// FIXME does not support Terms Of Service agreement
	w.WriteHeader(http.StatusCreated)
	output := newRegOutput{
		Contact: client.Contact,
		Jwk:     client.Key,
	}
	fmt.Println(output)
	acme.DefaultHeaderWithNonce(client, w)
	json.NewEncoder(w).Encode(output)
}
