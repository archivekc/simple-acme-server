package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	"model/constants"

	"strconv"

	"github.com/ProfOak/flag2"
)

// A CA is supposed to handle the certificate, crl, issuance stuff
type CA struct {
	Private           *rsa.PrivateKey
	Certificate       []byte
	ParsedCertificate *x509.Certificate
}

// PersistentSimpleCA is a CA that get it's private/pub from files
type PersistentSimpleCA struct {
	CA
}

// StupidCA class that represent a CA that create its private key itself
type StupidCA struct {
	CA
}

var certDuration = time.Duration(10*24) * time.Hour

// LoadCA create a persistent CA. If private key file does not exist, it creates it with a rsa key of 8192 bits.
// Expect PEM file format
func (ca *PersistentSimpleCA) LoadCA(parameters flag2.Options) {
	if _, err := os.Stat(parameters[constants.OptionsCaKeyPath].(string)); os.IsNotExist(err) || parameters[constants.OptionsRenewCa] == true {
		rsaKeySize, err := strconv.Atoi(parameters[constants.OptionsCaRsaKeySize].(string))
		if err != nil {
			panic(err)
		}
		// No private key, let's make one
		ca.Private, err = rsa.GenerateKey(rand.Reader, rsaKeySize)
		if err != nil {
			panic(err)
		}
		yearValidity, err := strconv.Atoi(parameters[constants.OptionsCaYearOfValidity].(string))
		if err != nil {
			panic(err)
		}
		tpl := x509.Certificate{
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Duration(yearValidity*24*365) * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:               true,
			SerialNumber:       big.NewInt(1),
			SignatureAlgorithm: x509.SHA256WithRSA,
			Subject: pkix.Name{
				Country:    []string{parameters[constants.OptionsCaCountry].(string)},
				CommonName: parameters[constants.OptionsCaCommonName].(string),
			},
		}
		ca.Certificate, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, &(ca.Private.PublicKey), ca.Private)
		if err != nil {
			panic(err)
		}
		b := x509.MarshalPKCS1PrivateKey(ca.Private)
		ioutil.WriteFile(parameters[constants.OptionsCaKeyPath].(string), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0700)
		ioutil.WriteFile(parameters[constants.OptionsCaCrtPath].(string), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate}), 0755)
	} else {
		if _, err := os.Stat(parameters[constants.OptionsCaCrtPath].(string)); os.IsNotExist(err) {
			yearValidity, err := strconv.Atoi(parameters[constants.OptionsCaYearOfValidity].(string))
			if err != nil {
				panic(err)
			}
			tpl := x509.Certificate{
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(time.Duration(yearValidity*24*365) * time.Hour),
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				IsCA:               true,
				SerialNumber:       big.NewInt(1),
				SignatureAlgorithm: x509.SHA256WithRSA,
				Subject: pkix.Name{
					Country:    []string{parameters[constants.OptionsCaCountry].(string)},
					CommonName: parameters[constants.OptionsCaCommonName].(string),
				},
			}
			ca.Certificate, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, &(ca.Private.PublicKey), ca.Private)
			if err != nil {
				panic(err)
			}
			ioutil.WriteFile(parameters[constants.OptionsCaCrtPath].(string), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate}), 0755)
		} else {
			ppemEncoded, err := ioutil.ReadFile(parameters[constants.OptionsCaKeyPath].(string))
			if err != nil {
				panic(err)
			}
			pp, _ := pem.Decode(ppemEncoded)
			ca.Private, err = x509.ParsePKCS1PrivateKey(pp.Bytes)
			if err != nil {
				panic(err)
			}
			pemEncoded, err := ioutil.ReadFile(parameters[constants.OptionsCaCrtPath].(string))
			if err != nil {
				panic(err)
			}
			p, _ := pem.Decode(pemEncoded)
			ca.Certificate = p.Bytes
		}
	}
	var err error
	ca.ParsedCertificate, err = x509.ParseCertificate(ca.Certificate)
	if err != nil {
		panic(err)
	}
}

// Init constructor of StupidCA
func (ca *StupidCA) init() {
	var err error
	ca.Private, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tpl := x509.Certificate{
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(10*24*365) * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:               true,
		SerialNumber:       big.NewInt(1),
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject: pkix.Name{
			Country:    []string{"FR"},
			CommonName: "Stupid CA don't use in production",
		},
	}
	ca.Certificate, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, &(ca.Private.PublicKey), ca.Private)
	if err != nil {
		panic(err)
	}
	ca.ParsedCertificate, err = x509.ParseCertificate(ca.Certificate)
	if err != nil {
		panic(err)
	}
	fmt.Println("Stupid CA private key")
	b := x509.MarshalPKCS1PrivateKey(ca.Private)
	pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: b})
	fmt.Println("Stupid CA public Certificate")
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate})
}

func decodeB64(data string) []byte {
	if m := len(data) % 4; m != 0 {
		data += strings.Repeat("=", 4-m)
	}
	pb, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	return pb
}

// CreateCert creates a certificate using the private and public key of the CA from the given csr
func (ca *CA) CreateCert(csr string) []byte {
	//fmt.Println("Stupid CA CSR to certified")
	//pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte(csr)})
	certReq, err := x509.ParseCertificateRequest(decodeB64(csr))
	if err != nil {
		panic(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(99999999))
	ccertReq := x509.Certificate{
		SerialNumber:          serial,
		Subject:               certReq.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:     false,
		DNSNames: certReq.DNSNames,
	}
	// cert is in der format
	cert, err := x509.CreateCertificate(rand.Reader, &ccertReq, ca.ParsedCertificate, certReq.PublicKey, ca.Private)
	if err != nil {
		panic(err)
	}
	return cert
}
