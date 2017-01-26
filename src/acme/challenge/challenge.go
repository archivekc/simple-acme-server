package challenge

import (
	"acme"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"jws"
	"model"
	"net/http"
	"time"
)

type infoInput struct {
	Type             string `json:"type"`
	KeyAuthorization string `json:"keyAuthorization"`
}

type infoOutput struct {
	Type             string `json:"type"`
	URI              string `json:"uri"`
	Status           string `json:"status"`
	Token            string `json:"token"`
	KeyAuthorization string `json:"keyAuthorization"`
}

// HandleInfo handle call for complementary data
func HandleInfo(server *model.AcmeServer, w http.ResponseWriter, r *http.Request) {
	content := acme.DebugRequest(r)

	// Check JWS
	client := server.Clients[acme.GetIP(r)]

	if r.Method == "GET" {
		challenge := client.Authorizations[0].Challenges[0]
		response := infoOutput{
			Type:             "http-01",
			Token:            challenge.Token,
			Status:           challenge.Status,
			URI:              challenge.URI,
			KeyAuthorization: challenge.KeyAuthorization,
		}
		fmt.Println(response)
		acme.DefaultHeader(client, w)
		w.Header().Set("Replay-After", "15")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	} else {
		payload, _ := jws.ValidateJws(client, w, content)
		var input infoInput
		err := json.Unmarshal(payload, &input)
		if err != nil {
			panic(err)
		}
		if input.Type != "http-01" {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			authorization := client.Authorizations[0]
			challenge := authorization.Challenges[0]
			challenge.KeyAuthorization = input.KeyAuthorization
			response := infoOutput{
				Type:             "http-01",
				Token:            challenge.Token,
				Status:           challenge.Status,
				URI:              challenge.URI,
				KeyAuthorization: challenge.KeyAuthorization,
			}
			fmt.Println(response)
			acme.DefaultHeaderWithNonce(client, w)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
			go validHTTP01(authorization, challenge)
		}
	}
}

func validHTTP01(auth *model.Authorization, challenge *model.Challenge) {
	fmt.Println("valid http-01", auth.CommonName)
	url := "http://"
	url += auth.CommonName
	url += "/.well-known/acme-challenge/"
	url += challenge.Token
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("challenge http-01 failed, url not accessible", err.Error())
		challenge.Status = "invalid"
		auth.Status = "invalid"
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if string(body) == challenge.KeyAuthorization {
		// should be keyauth
		fmt.Println("validated http-01", auth.CommonName)
		challenge.Status = "valid"
		auth.Status = "valid"
	} else {
		fmt.Println("validation http-01 failed", auth.CommonName)
		challenge.Status = "invalid"
		auth.Status = "invalid"
	}
	challenge.Validated = time.Now()
}
