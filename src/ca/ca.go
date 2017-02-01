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
func (ca *PersistentSimpleCA) LoadCA(privateKeyPath, certKeyPath string) {
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		// No private key, let's make one
		ca.Private, err = rsa.GenerateKey(rand.Reader, 8192)
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
				CommonName: "Internal CA",
			},
		}
		ca.Certificate, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, &(ca.Private.PublicKey), ca.Private)
		if err != nil {
			panic(err)
		}
		b := x509.MarshalPKCS1PrivateKey(ca.Private)
		ioutil.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0700)
		ioutil.WriteFile(certKeyPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate}), 0755)
	} else {
		if _, err := os.Stat(certKeyPath); os.IsNotExist(err) {
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
					CommonName: "Internal CA",
				},
			}
			ca.Certificate, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, &(ca.Private.PublicKey), ca.Private)
			if err != nil {
				panic(err)
			}
			ioutil.WriteFile(certKeyPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate}), 0755)
		} else {
			pemEncoded, err := ioutil.ReadFile(certKeyPath)
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
func (ca *StupidCA) Init() {
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
	fmt.Println(data)
	pb, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	return pb
}

// CreateCert creates a certificate using the private and public key of the CA from the given csr
func (ca *CA) CreateCert(csr string) []byte {
	fmt.Println("Stupid CA CSR to certified")
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
