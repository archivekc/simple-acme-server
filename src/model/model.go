package model

import "time"

// FIXME when validation jws is done, check if it can be send back to jws.go

// JWK part of JWS message
type JWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

//AcmeServer represents the configuration of this AcmeServer
type AcmeServer struct {
	Hostname string
	Port     string
	Clients  map[string]*RegisterClient
}

// RegisterClient : a registered clients with its authorization and challenges
type RegisterClient struct {
	Nonce          string
	Contact        []string
	Key            JWK
	Authorizations []*Authorization
}

// Authorization represents an authorization for a dns name with associated challenges
type Authorization struct {
	CommonName string
	Status     string
	Challenges []*Challenge
}

// Challenge hold the status of authorization challenges
type Challenge struct {
	Status           string
	Type             string
	Token            string
	URI              string
	KeyAuthorization string
	Validated        time.Time
}
