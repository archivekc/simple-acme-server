package main

import (
	"acme/authorization"
	"acme/certificate"
	"acme/challenge"
	"acme/directory"
	"acme/register"
	"acme/www"
	"ca"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"model"
	"model/constants"
	"net"
	"net/http"
	"os"

	"github.com/ProfOak/flag2"
	"github.com/jasonlvhit/gocron"

	"encoding/base64"

	"crypto/tls"
)

func defaultHandle(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Url:", html.EscapeString(r.URL.Path))
	fmt.Println("Header:", r.Header)
	content, _ := ioutil.ReadAll(r.Body)
	fmt.Println("Body:", string(content))
}

func initServer(acmes *model.AcmeServer) {
	if _, err := os.Stat("server.key"); os.IsNotExist(err) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		b := x509.MarshalPKCS1PrivateKey(priv)
		ioutil.WriteFile("server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0700)
		tpl := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: acmes.Hostname,
			},
			Version:   1,
			PublicKey: &priv.PublicKey,
			DNSNames: []string{
				acmes.Hostname,
			},
			EmailAddresses: []string{},
			IPAddresses:    []net.IP{},
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &tpl, priv)
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile("server.csr", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), 0755)
	}
	renewServerCrtAndServe(acmes)
}

func renewServerCrtAndServe(acmes *model.AcmeServer) {
	fmt.Println("Renewing server certificate")
	csr, err := ioutil.ReadFile("server.csr")
	if err != nil {
		panic(err)
	}
	pcsr, _ := pem.Decode(csr)
	cert := acmes.CA.CreateCert(base64.RawURLEncoding.EncodeToString(pcsr.Bytes))
	serverCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	caCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: acmes.CA.Certificate})
	fullChain := append(serverCert, caCert...)
	ioutil.WriteFile("server.crt", fullChain, 0755)

	// serve or reloadServer
	go reloadServer(acmes)
}

func reloadServer(acmes *model.AcmeServer) {
	if acmes.Listener != nil {
		err := acmes.Listener.Close()
		if err != nil {
			log.Fatal(err)
		}
	}

	// Set up server
	acmes.HTTPServer = http.Server{
		Handler:   nil,
		TLSConfig: new(tls.Config),
	}
	crt, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		panic(err)
	}
	acmes.HTTPServer.TLSConfig.Certificates = []tls.Certificate{crt}
	// Set listener
	l, err := tls.Listen("tcp", ":"+acmes.Port, acmes.HTTPServer.TLSConfig)
	if err != nil {
		panic(err)
	}
	acmes.Listener = l
	fmt.Println("Restart web server with renew certificate on " + acmes.Hostname + ":" + acmes.Port)
	acmes.HTTPServer.Serve(acmes.Listener)
}

func setUpParameters() flag2.Options {
	f := flag2.NewFlag()

	// Server Config
	f.AddString("", constants.OptionsHostname, "Server hostname (ssl common name)", "localhost")
	f.AddString("p", constants.OptionsPort, "Server port", "443")

	// Server key file
	f.AddString("k", constants.OptionsCaKeyPath, "CA key pem path", "ca_key.pem")
	f.AddString("c", constants.OptionsCaCrtPath, "CA crt pem path", "ca_crt.pem")
	f.AddBool("r", constants.OptionsRenewCa, "Renew CA", false)

	// Server root CA config
	f.AddString("s", constants.OptionsCaRsaKeySize, "CA key bits size", "8192")
	f.AddString("y", constants.OptionsCaYearOfValidity, "Duration of self-signed CA in year", "10")
	f.AddString("o", constants.OptionsCaCountry, "Country of self signed", "FR")
	f.AddString("n", constants.OptionsCaCommonName, "Common name of self signed", "Internal CA")

	// a help flag is added during the parse step
	options, _ := f.Parse(os.Args)
	fmt.Println("Start with options:", options)
	// unfortunate side effect of interfaces
	if options["help"] == true {
		f.Usage()
		os.Exit(0)
	}
	return options
}

func main() {
	parameters := setUpParameters()

	server := model.AcmeServer{
		Hostname: parameters[constants.OptionsHostname].(string),
		Port:     parameters[constants.OptionsPort].(string),
		CA:       new(ca.PersistentSimpleCA),
		Clients:  make(map[string]*model.RegisterClient),
	}
	server.Load()
	server.CA.LoadCA(parameters)

	http.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		directory.HandleDirectory(&server, w, r)
	})
	http.HandleFunc("/new-reg", func(w http.ResponseWriter, r *http.Request) {
		register.HandleNewRegistration(&server, w, r)
	})
	http.HandleFunc("/new-authz", func(w http.ResponseWriter, r *http.Request) {
		authorization.HandleNewAuthorization(&server, w, r)
	})
	http.HandleFunc("/authz/asdf/", func(w http.ResponseWriter, r *http.Request) {
		challenge.HandleInfo(&server, w, r)
	})
	http.HandleFunc("/cert/new-cert", func(w http.ResponseWriter, r *http.Request) {
		certificate.HandleNewCert(&server, w, r)
	})
	http.HandleFunc("/cert/crt/", func(w http.ResponseWriter, r *http.Request) {
		certificate.HandleUniqueCertUri(&server, w, r)
	})
	http.HandleFunc("/cert/", func(w http.ResponseWriter, r *http.Request) {
		certificate.HandleGetCert(&server, w, r)
	})
	http.HandleFunc("/cert/ca", func(w http.ResponseWriter, r *http.Request) {
		certificate.HandleCACertificate(&server, parameters[constants.OptionsCaCommonName].(string), w, r)
	})
	http.HandleFunc("/cert/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		certificate.HandleCACertificatePem(&server, parameters[constants.OptionsCaCommonName].(string), w, r)
	})
	/*
		http.HandleFunc("/authz/asdf", handleRequestStatus)
		http.HandleFunc("/recover-reg", defaultHandle)
		http.HandleFunc("/new-cert", defaultHandle)
		http.HandleFunc("/revoke-cert", defaultHandle)
	*/
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		www.ServeTemplate("doc_en.html", &server, w, r)
	})

	// start http server
	go initServer(&server)

	// renew server cert
	gocron.Every(8).Days().Do(renewServerCrtAndServe, &server)
	<-gocron.Start()

	//log.Fatal(http.Serve(listener, nil))
	//log.Fatal(http.ListenAndServeTLS(":"+server.Port, "server.crt", "server.key", nil))
}
