package certificate

import (
	"acme"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"jws"
	"model"
	"net/http"
	"time"
)

type newCertInput struct {
	CSR      string `json:"csr"`
	Resource string `json:"resource"`
}

type newOrderInput struct {
	CSR    string    `json:"csr"`
	Before time.Time `json:"notBefore"`
	After  time.Time `json:"notAfter"`
}

type newOrderOutput struct {
	Status         string    `json:"status"`
	Expires        time.Time `json:"expires"`
	CSR            string    `json:"csr"`
	Before         time.Time `json:"notBefore"`
	After          time.Time `json:"notAfter"`
	Authorisations []string  `json:"authorizations"`
	CertificateURI string    `json:"certificate"`
}

var timeToComplete, _ = time.ParseDuration("24h")

// HandleNewCert handle the new cert draft way
func HandleNewCert(server *model.AcmeServer, w http.ResponseWriter, r *http.Request) {
	content := acme.DebugRequest(r)
	client := server.Clients[acme.GetIP(r)]
	payload, _ := jws.ValidateJws(client, w, content)
	var input newCertInput
	json.Unmarshal(payload, &input)
	fmt.Println(string(payload))

	// look for existing and if none (should be the case) add an object
	hash := fmt.Sprintf("%x", md5.Sum([]byte(input.CSR)))
	certRequest := client.CertificateRequests[hash]
	if certRequest == nil {
		certRequest = new(model.CertificateRequest)
		certRequest.CSR = input.CSR
		certRequest.OrderURI = "https://" + server.Hostname + ":" + server.Port + "/cert/order/" + hash
		certRequest.URI = "https://" + server.Hostname + ":" + server.Port + "/cert/" + hash
		certRequest.Certificates = make(map[string]*model.Certificate)
		client.CertificateRequests[hash] = certRequest
	}
	// FIXME explore csr to map to all Authorizations, for now just say it is processing

	acme.DefaultHeaderWithNonce(client, w)
	w.Header().Set("Location", certRequest.URI)
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(http.StatusCreated)
	go createCert(certRequest, server)
}

func createCert(certificate *model.CertificateRequest, server *model.AcmeServer) {
	crt := new(model.Certificate)
	crt.CRT = server.CA.CreateCert(certificate.CSR)
	hash := fmt.Sprintf("%x", md5.Sum(crt.CRT))
	crt.URI = "https://" + server.Hostname + ":" + server.Port + "/cert/crt/" + hash
	certificate.OrderStatus = "valid"
	certificate.Last = crt
	certificate.Certificates[hash] = crt
}

func HandleUniqueCertUri(server *model.AcmeServer, w http.ResponseWriter, r *http.Request) {
	acme.DebugRequest(r)
	client := server.Clients[acme.GetIP(r)]
	hash := acme.GetLastPart(r)

	for _, csr := range client.CertificateRequests {
		if csr.Certificates[hash] != nil {
			w.Header().Set("Link", "<https://"+server.Hostname+":"+server.Port+"/cert/ca>;rel=\"up\";title=\"issuer\"")
			w.Header().Set("Link", "<https://"+server.Hostname+":"+server.Port+"/cert/revoke>;rel=\"revoke\"")
			w.Header().Set("Link", "<"+client.URI+">;rel=\"author\"")
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.WriteHeader(http.StatusOK)
			response := base64.RawURLEncoding.EncodeToString(csr.Certificates[hash].CRT)
			w.Write([]byte(response))
			return
		}
	}
}

func HandleCACertificate(server *model.AcmeServer, w http.ResponseWriter, r *http.Request) {
	acme.DebugRequest(r)
	if r.Header.Get("Content-Type") == "application/x-pem-file" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.CA.Certificate}))
	} else {
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.WriteHeader(http.StatusOK)
		w.Write(server.CA.Certificate)
	}
}

func HandleGetCert(server *model.AcmeServer, w http.ResponseWriter, r *http.Request) {
	acme.DebugRequest(r)
	client := server.Clients[acme.GetIP(r)]
	hash := acme.GetLastPart(r)

	certificate := client.CertificateRequests[hash]
	if certificate == nil {
		fmt.Println("Unable to find certificate")
		w.WriteHeader(http.StatusNotFound)
	} else {
		if certificate.Last.CRT != nil {
			fmt.Println("Transfer certificate")
			// Here cert is ready
			//response := "-----BEGIN CERTIFICATE-----\n"
			//response += base64.RawURLEncoding.EncodeToString(certificate.Last.CRT)
			//response += "\n-----END CERTIFICATE-----"
			//crtPem := pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: certificate.Last.CRT})
			//response := base64.RawURLEncoding.EncodeToString(crtPem)

			w.Header().Add("Link", "<https://"+server.Hostname+":"+server.Port+"/cert/ca>;rel=\"up\";title=\"issuer\"")
			w.Header().Add("Link", "<https://"+server.Hostname+":"+server.Port+"/cert/revoke>;rel=\"revoke\"")
			w.Header().Add("Link", "<https://"+server.Hostname+":"+server.Port+"/directory>;rel=\"directory\"")
			w.Header().Add("Link", "<"+client.URI+">;rel=\"author\"")
			w.Header().Set("Location", certificate.URI)
			w.Header().Set("Content-Location", certificate.Last.URI)
			if r.Header.Get("Content-Type") == "application/pkix-cert" {
				w.Header().Set("Content-Type", "application/pkix-cert")
				w.WriteHeader(http.StatusCreated)
				w.Write(certificate.Last.CRT)
			} else {
				w.Header().Set("Content-Type", "application/x-pem-file")
				w.WriteHeader(http.StatusCreated)
				w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Last.CRT}))
			}
		} else {
			// Please retry later
			acme.DefaultHeader(client, w)
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusAccepted)
		}
	}
}

// HandleNewOrder it is for new order part
func HandleNewOrder(server *model.AcmeServer, w http.ResponseWriter, r *http.Request) {
	content := acme.DebugRequest(r)
	client := server.Clients[acme.GetIP(r)]
	payload, _ := jws.ValidateJws(client, w, content)
	var input newOrderInput
	json.Unmarshal(payload, &input)
	fmt.Println(string(payload))

	// look for existing and if none (should be the case) add an object
	hash := fmt.Sprintf("%x", md5.Sum([]byte(input.CSR)))
	certificate := client.CertificateRequests[hash]
	if certificate == nil {
		certificate = new(model.CertificateRequest)
		certificate.CSR = input.CSR
		certificate.OrderURI = "https://" + server.Hostname + ":" + server.Port + "/cert/order/" + hash
		certificate.URI = "https://" + server.Hostname + ":" + server.Port + "/cert/" + hash
		client.CertificateRequests[hash] = certificate
	}
	certificate.NotBefore = input.Before
	certificate.NotAfter = input.After
	certificate.OrderExpires = time.Now().Add(timeToComplete)
	// FIXME explore csr to map to all Authorizations, for now just say it is processing
	certificate.OrderStatus = "processing"

	response := newOrderOutput{
		Status:         certificate.OrderStatus,
		Expires:        certificate.OrderExpires,
		CSR:            certificate.CSR,
		Before:         certificate.NotBefore,
		After:          certificate.NotAfter,
		Authorisations: []string{},
		CertificateURI: certificate.URI,
	}
	acme.DefaultHeaderWithNonce(client, w)
	w.Header().Set("Location", certificate.OrderURI)
	w.Header().Set("Retry-After", "15")
	w.WriteHeader(http.StatusCreated)
	fmt.Println(response)
	json.NewEncoder(w).Encode(response)
}
