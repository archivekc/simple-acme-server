package model

import (
	"ca"
	"net"
	"net/http"
	"time"
)

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
	Hostname   string
	Port       string
	CA         *ca.PersistentSimpleCA
	Clients    map[string]*RegisterClient
	Listener   net.Listener
	HTTPServer http.Server
}

// RegisterClient : a registered clients with its authorization and challenges
type RegisterClient struct {
	Nonce               string
	Contact             []string
	Key                 JWK
	Authorizations      []*Authorization
	CertificateRequests map[string]*CertificateRequest
	URI                 string
}

// CertificateRequest that holds CSR
type CertificateRequest struct {
	CSR          string
	NotBefore    time.Time
	NotAfter     time.Time
	OrderStatus  string
	OrderExpires time.Time
	OrderURI     string
	URI          string
	Last         *Certificate
	Certificates map[string]*Certificate
}

// Certificate hold data related to a client certificate
type Certificate struct {
	URI string
	CRT []byte
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
