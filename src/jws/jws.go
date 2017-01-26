package jws

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"model"

	"net/http"

	jose "gopkg.in/square/go-jose.v2"
)

type b64JWS struct {
	Payload   string `json:"payload"`
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

// Protected protected part of JWS message
type Protected struct {
	ALG   string    `json:"alg"`
	JWK   model.JWK `json:"jwk"`
	Nonce string    `json:"nonce"`
}

// ValidateJws Validate a jws and return the payload decrypt from base64 and the protected. Also validate non replay nonce
func ValidateJws(client *model.RegisterClient, w http.ResponseWriter, payload []byte) ([]byte, Protected) {
	// First validate Signature
	_, err := jose.ParseSigned(string(payload))
	if err != nil {
		panic(err)
	}
	// FIXME validate signature but what is the key ?

	jws := decodeJWS(payload)
	decodedPayload := decodeB64(jws.Payload)
	var protected Protected
	err = json.Unmarshal(decodeB64(string(jws.Protected)), &protected)
	if err != nil {
		panic(err)
	}
	if client.Nonce != string(decodeB64(protected.Nonce)) {
		fmt.Println("Nonce in memory is", client.Nonce)
		fmt.Println("Nonce received is", string(decodeB64(protected.Nonce)))
		w.Header().Set("error", "urn:ietf:params:acme:error:badNonce")
		w.WriteHeader(http.StatusBadRequest)
		panic("Bad nonce")
	}
	return decodedPayload, protected
}

func decodeJWS(payload []byte) b64JWS {
	var b b64JWS
	err := json.Unmarshal(payload, &b)
	if err != nil {
		panic(err)
	}
	return b
}

func decodeB64(data string) []byte {
	if m := len(data) % 4; m != 0 {
		data += strings.Repeat("=", 4-m)
	}
	pb, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	return pb
}
