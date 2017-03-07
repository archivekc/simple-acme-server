package model

import (
	"ca"
	"encoding/json"
	"io/ioutil"
	"model/constants"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// FIXME when validation jws is done, check if it can be send back to jws.go

// JWK part of JWS message
type JWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JSONTime to hold a time and have a marshaller
type JSONTime struct {
	Value time.Time
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
	NotBefore    JSONTime
	NotAfter     JSONTime
	OrderStatus  string
	OrderExpires JSONTime
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
	Validated        JSONTime
	AttemptLeft      int
}

var saveLock = &sync.Mutex{}

// Save to disc clients
func (serv *AcmeServer) Save() {
	saveLock.Lock()
	sav, err := json.Marshal(serv.Clients)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(constants.DatabaseFileName, sav, 0600)
	if err != nil {
		panic(err)
	}
	saveLock.Unlock()
}

// Load from disc clients
func (serv *AcmeServer) Load() {
	if _, err := os.Stat(constants.DatabaseFileName); !os.IsNotExist(err) {
		sav, err := ioutil.ReadFile(constants.DatabaseFileName)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(sav, &serv.Clients)
		if err != nil {
			panic(err)
		}
	}
}

func (t JSONTime) MarshalJSON() ([]byte, error) {
	result := t.Value.Format(constants.TimeFormat)
	return []byte(result), nil
}

func (t JSONTime) UnmarshalJSON(v []byte) error {
	var err error
	t.Value, err = time.Parse(constants.TimeFormat, string(v))
	return err
}
