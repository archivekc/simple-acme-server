package authorization

import (
	"acme"
	"encoding/json"
	"fmt"
	"jws"
	"model"
	"net/http"
)

// 6.5. Identifier Authorization

type authzIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type newAuthzChallenge struct {
	Type  string `json:"type"`
	URI   string `json:"uri"`
	Token string `json:"token"`
}

type newAuthzInput struct {
	Resource   string          `json:"resource"`
	Identifier authzIdentifier `json:"identifier"`
}

type newAuthzOutput struct {
	Status       string              `json:"status"`
	Identifier   authzIdentifier     `json:"identifier"`
	Challenges   []newAuthzChallenge `json:"challenges"`
	Combinations [][]int             `json:"combinations"`
}

//HandleNewAuthorization deal with new authz
func HandleNewAuthorization(server *model.AcmeServer, w http.ResponseWriter, r *http.Request) {
	body := acme.DebugRequest(r)
	client := server.Clients[acme.GetIP(r)]

	payload, _ := jws.ValidateJws(client, w, body)
	var input newAuthzInput
	json.Unmarshal(payload, &input)
	if input.Identifier.Type != "dns" {
		w.WriteHeader(http.StatusForbidden)
	} else {
		token := acme.CreateNonce(32)
		c := new(model.Challenge)
		c.Status = "pending"
		c.Type = "http-01"
		c.URI = "https://" + server.Hostname + ":" + server.Port + "/authz/asdf/" + token
		c.Token = token

		authorization := new(model.Authorization)

		authorization.CommonName = input.Identifier.Value
		authorization.Status = "pending"
		authorization.Challenges = []*model.Challenge{c}

		client.Authorizations = append(client.Authorizations, authorization)
		server.Save()

		response := newAuthzOutput{
			Status:     authorization.Status,
			Identifier: input.Identifier,
			Challenges: []newAuthzChallenge{
				newAuthzChallenge{
					Type:  "http-01",
					URI:   c.URI,
					Token: c.Token,
				},
			},
			Combinations: [][]int{[]int{0}},
		}

		acme.DefaultHeaderWithNonce(client, w)
		w.Header().Set("Location", "https://"+server.Hostname+":"+server.Port+"/authz/asdf")
		w.Header().Set("Link", "<https://"+server.Hostname+":"+server.Port+"/cert/new-cert>;rel=\"next\"")
		w.WriteHeader(http.StatusCreated)
		fmt.Println(response)
		json.NewEncoder(w).Encode(response)
	}
}
