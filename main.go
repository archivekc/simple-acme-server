package main

import (
	"acme/authorization"
	"acme/challenge"
	"acme/directory"
	"acme/register"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"model"
	"net/http"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

type Registration struct {
	Contact  []string `json:"contact"`
	Nonce    string
	Key      JWSJWK `json:"key"`
	Requests []Request
}

type Request struct {
	DNS       string
	Status    string
	Validated time.Time
}

type JWSChallenge struct {
	Resource         string `json:"resource"`
	Type             string `json:"type"`
	TLS              bool   `json:"tls"`
	KeyAuthorization string `json:"keyAuthorization"`
}

type JWSJWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type JWSConfirmedAuthzChallenge struct {
	Type             string `json:"type"`
	URI              string `json:"uri"`
	Token            string `json:"token"`
	TLS              bool   `json:"tls"`
	Status           string `json:"status"`
	Resource         string `json:"resource"`
	KeyAuthorization string `json:"keyAuthorization"`
}

/*func createJwt(serverName, source string) string {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, &jose.SignerOptions{})
	if err != nil {
		panic(err)
	}

	cl := jwt.Claims{
		Subject:   "acme",
		Issuer:    serverName,
		NotBefore: jwt.NewNumericDate(time.Now()),
		Audience:  jwt.Audience{source},
	}
	raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
	if err != nil {
		panic(err)
	}
	fmt.Println(raw)
	return raw
}*/

func createJws(privateKey, payload []byte) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: privateKey}, &jose.SignerOptions{})
	if err != nil {
		panic(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	serialized := object.FullSerialize()

	fmt.Println(serialized)
	return serialized
}

/*
	func validateJwsAuthz(privateKey string, payload []byte) *JWSNewAuthzPayload {
		var b b64JWS
		var v JWSNewAuthzPayload
		err := json.Unmarshal(payload, &b)
		if err != nil {
			panic(err)
		}
		if m := len(b.Payload) % 4; m != 0 {
			b.Payload += strings.Repeat("=", 4-m)
		}
		pb, err := base64.StdEncoding.DecodeString(b.Payload)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(pb, &v)
		if err != nil {
			panic(err)
		}

		fmt.Println(v)
		_, err = jose.ParseSigned(string(payload))
		if err != nil {
			panic(err)
		}
		// FIXME Need to check Signature but can't managed to do so
		output, err := object.Verify([]byte(privateKey))
		if err != nil {
			panic(err)
		}
	return &v
	//return output

}

func validateJwsChallenge(privateKey string, payload []byte) *JWSChallenge {
	fmt.Println("=====================> ", string(payload))
	var b b64JWS
	var v JWSChallenge
	err := json.Unmarshal(payload, &b)
	if err != nil {
		panic(err)
	}
	if m := len(b.Payload) % 4; m != 0 {
		b.Payload += strings.Repeat("=", 4-m)
	}
	pb, err := base64.StdEncoding.DecodeString(b.Payload)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pb))
	err = json.Unmarshal(pb, &v)
	if err != nil {
		panic(err)
	}

	fmt.Println(v)
	_, err = jose.ParseSigned(string(payload))
	if err != nil {
		panic(err)
	}
	// FIXME Need to check Signature but can't managed to do so
	output, err := object.Verify([]byte(privateKey))
	if err != nil {
		panic(err)
	}
	return &v
	//return output

}*/

/*
func validateSimpleHTTP(privateKey string, payload []byte) *JWSNewAuthzChallenge {
	fmt.Println("Chalenger content> ", string(payload))
	var b b64JWS
	var v JWSNewAuthzChallenge
	err := json.Unmarshal(payload, &b)
	if err != nil {
		panic(err)
	}
	if m := len(b.Payload) % 4; m != 0 {
		b.Payload += strings.Repeat("=", 4-m)
	}
	pb, err := base64.StdEncoding.DecodeString(b.Payload)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(pb, &v)
	if err != nil {
		panic(err)
	}

	fmt.Println(v)
	_, err = jose.ParseSigned(string(payload))
	if err != nil {
		panic(err)
	}
	// FIXME Need to check Signature but can't managed to do so
	///output, err := object.Verify([]byte(privateKey))
	return &v
	//return output

}


func handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	client := nonceMap[getIP(r)]
	authorization := client.Requests[0]
	if authorization.Status == "pending" {
		w.Header().Set("Retry-After", "15")
		w.WriteHeader(http.StatusAccepted)
	} else {
		response := JWSNewAuthzResponse{
			Status: authorization.Status,
			Identifier: JWSNewAuthzIdentifier{
				Type:  "dns",
				Value: authorization.DNS,
			},
			Challenges: []JWSNewAuthzChallenge{
				JWSNewAuthzChallenge{
					Status:    authorization.Status,
					Type:      "simpleHttp",
					Token:     authorization.Challenge.Token,
					Validated: authorization.Validated,
				}},
		}

		w.WriteHeader(http.StatusOK)
		debug, _ := json.Marshal(response)
		fmt.Println(string(debug))
		json.NewEncoder(w).Encode(response)
	}

}






*/
func defaultHandle(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Url:", html.EscapeString(r.URL.Path))
	fmt.Println("Header:", r.Header)
	content, _ := ioutil.ReadAll(r.Body)
	fmt.Println("Body:", string(content))
}

func main() {
	server := model.AcmeServer{
		Hostname: "kco12.nantes.keyconsulting.fr",
		Port:     "81",
		Clients:  make(map[string]*model.RegisterClient),
	}

	http.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		directory.HandleDirectory(&server, w, r)
	})
	http.HandleFunc("/new-reg", func(w http.ResponseWriter, r *http.Request) {
		register.HandleNewRegistration(&server, w, r)
	})
	http.HandleFunc("/new-authz", func(w http.ResponseWriter, r *http.Request) {
		authorization.HandleNewAuthorization(&server, w, r)
	})
	http.HandleFunc("/authz/asdf/0", func(w http.ResponseWriter, r *http.Request) {
		challenge.HandleInfo(&server, w, r)
	})
	/*
		http.HandleFunc("/authz/asdf", handleRequestStatus)
		http.HandleFunc("/recover-reg", defaultHandle)
		http.HandleFunc("/new-cert", defaultHandle)
		http.HandleFunc("/revoke-cert", defaultHandle)
	*/
	http.HandleFunc("/", defaultHandle)

	log.Fatal(http.ListenAndServeTLS(":81", "server.crt", "server.key", nil))

}